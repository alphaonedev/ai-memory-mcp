// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Memory CRUD HTTP handlers — `get_memory`, `update_memory`,
//! `delete_memory`, and `promote_memory`.
//!
//! Extracted from [`super::http`] under issue #650 (handler cap ≤1200
//! LOC). Handler bodies are unchanged; only the module surface moved.
//! Wire compatibility preserved via `pub use memories::*` in [`super`].

#![allow(clippy::too_many_lines)]

use crate::models::field_names;
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json::json;

use crate::db;
use crate::identity::sentinels;
use crate::models::{Tier, UpdateMemory};
use crate::validate;

use super::AppState;
#[cfg(feature = "sal")]
use super::StorageBackend;
#[cfg(feature = "sal")]
use super::store_err_to_response;

pub async fn get_memory(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = validate::validate_id(&id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }

    // #2044 (#2032-A / H1 IDOR) — per-agent-key identity gate BEFORE the
    // ownership / visibility check.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "get_memory",
    ) {
        return resp;
    }

    // v0.7.0 Wave-3 — Postgres-backed daemons dispatch through the
    // SAL trait. The legacy `db::resolve_id` path is SQLite-bound (it
    // walks `memories` + `memory_links` directly through the
    // mutex-guarded rusqlite connection); routing the postgres branch
    // through `app.store` keeps the wire-shape identical while
    // hitting the right backend. SQLite-backed daemons keep the
    // legacy direct-rusqlite path for v0.7.0 binary parity.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // #910 SAL-level — resolve the caller from `X-Agent-Id` so the
        // SAL `get` filter has a known principal. Header-only auth on
        // this GET surface; anonymous callers get a per-request
        // `anonymous:req-…` id and see only non-private rows. Bound
        // inside the cfg block so default-features builds don't flag
        // it as unused.
        let header_agent_id = headers
            .get(crate::HEADER_AGENT_ID)
            .and_then(|v| v.to_str().ok());
        let caller = crate::identity::resolve_http_agent_id(None, header_agent_id)
            .unwrap_or_else(|_| crate::identity::anonymous_request_id());
        let ctx = crate::store::CallerContext::for_agent(&caller);
        return match app.store.get(&ctx, &id).await {
            Ok(mem) => {
                // List_links surfaces the full edge set (no namespace
                // filter) so the postgres adapter's `list_links` walks
                // its `memory_links` table and the local-side filter
                // narrows to edges anchored at this memory id.
                let edges = match app.store.list_links(None).await {
                    Ok(rows) => rows
                        .into_iter()
                        .filter(|l| l.source_id == mem.id || l.target_id == mem.id)
                        .collect::<Vec<_>>(),
                    Err(e) => {
                        tracing::warn!(
                            "store.list_links during get_memory failed: {e}; \
                             returning memory with empty links"
                        );
                        Vec::new()
                    }
                };
                Json(json!({"memory": mem, "links": edges})).into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    // #927 SECURITY-medium (Track A P4, 2026-05-20): apply the
    // scope=private visibility filter on the sqlite GET-by-id path.
    // Pre-fix Bob could fetch Alice's scope=private row by id — the
    // single-record GET surface didn't extract X-Agent-Id and didn't
    // gate on ownership. Mirrors the postgres SAL branch above which
    // routes through `app.store.get(&ctx, &id)` with caller context.
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let caller = crate::identity::resolve_http_agent_id(None, header_agent_id)
        .unwrap_or_else(|_| crate::identity::anonymous_request_id());

    // #1580 (PERF, supersedes the PERF-1/FX-3 `db_op` wrap): `get_memory`
    // is a pure read (resolve_id + get_links), so it dispatches through
    // the WAL read-pool (`db_read_op`) instead of the single writer
    // mutex — concurrent GETs now run on distinct read-only connections
    // rather than serializing. The visibility check is pure CPU on the
    // owned Memory so it stays outside the helper; only the SELECTs touch
    // a pool connection.
    let id_clone = id.clone();
    let lookup: Result<
        Option<(crate::models::Memory, Vec<crate::models::MemoryLink>)>,
        anyhow::Error,
    > = super::read_pool::db_read_op(app.db.clone(), move |conn| {
        match db::resolve_id(conn, &id_clone) {
            Ok(Some(mem)) => {
                // #869 audit (Category B — safe default): a substrate
                // failure on `get_links` is non-fatal — the memory
                // body itself was retrieved cleanly. Empty `links`
                // array degrades graph navigation rather than
                // failing the GET.
                let links = db::get_links(conn, &mem.id).unwrap_or_default();
                Ok(Some((mem, links)))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    })
    .await;
    match lookup {
        Ok(Some((mem, links))) => {
            // #927 — 404 (not 403) on a private-row read by a non-owner
            // matches the existing visibility convention: returning
            // 403 would leak the existence of a row the caller is not
            // entitled to know about.
            //
            // #951 (Track A QC sweep, 2026-05-20) — delegated to the
            // canonical `crate::visibility::is_visible_to_caller`
            // helper. Pre-#951 the inline check duplicated the
            // semantic at risk of drifting from the SAL version.
            if !crate::visibility::is_visible_to_caller(&mem, &caller) {
                tracing::warn!(
                    target: "ai_memory::visibility",
                    "GET /memories/{{id}} 404-masked: not visible to caller {caller} (id={})",
                    mem.id
                );
                return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})))
                    .into_response();
            }
            Json(json!({"memory": mem, "links": links})).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
        Err(e) => {
            // #962 — typed downcast (was: msg.contains("ambiguous ID
            // prefix")). The substrate emits `StorageError::AmbiguousIdPrefix`
            // wrapped in anyhow; surface 400 with the typed Display body
            // (byte-identical to the legacy bail!() string).
            //
            // SAL-bypass intentional (#961): the SAL `StoreError` enum
            // (`src/store/mod.rs`) does not carry the
            // `AmbiguousIdPrefix` variant — id-prefix resolution lives
            // on the legacy `db::resolve_id` free-function which
            // returns `anyhow::Error`-wrapped `StorageError`. The
            // typed downcast is required to map the 400 envelope; the
            // pattern repeats four more times in this file (update,
            // delete, promote, plus this get path). The postgres
            // branch above never reaches here because it dispatches
            // through `app.store.get` which has its own typed
            // `StoreError::NotFound`/`InvalidInput` shape.
            if matches!(
                e.downcast_ref::<crate::storage::StorageError>(),
                Some(crate::storage::StorageError::AmbiguousIdPrefix { .. })
            ) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
            crate::handlers::errors::handler_error_500(&e)
        }
    }
}

/// #1628 — extract the stored `version` from the postgres
/// `update_with_expected_version` conflict detail (shape:
/// `"VersionConflict: memory <id> expected_version=<e> but stored version=<c>"`,
/// minted in `src/store/postgres.rs`). Returns `None` for any other
/// `IntegrityFailed` detail so non-conflict failures keep their
/// generic `store_err_to_response` mapping.
#[cfg(feature = "sal")]
fn parse_pg_conflict_stored_version(detail: &str) -> Option<i64> {
    detail
        .strip_prefix("VersionConflict: memory ")?
        .rsplit("stored version=")
        .next()?
        .trim()
        .parse()
        .ok()
}

#[allow(clippy::too_many_lines)]
pub async fn update_memory(
    State(app): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdateMemory>,
) -> impl IntoResponse {
    let state = app.db.clone();
    if let Err(e) = validate::validate_id(&id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }
    // #2044 (#2032-A / H1 IDOR) — per-agent-key identity gate.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "update_memory",
    ) {
        return resp;
    }
    if let Err(e) = validate::RequestValidator::validate_update(&body) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }
    // v0.7.0 Provenance Gap 1 (#884) — `If-Match: <version>` opt-in
    // optimistic-concurrency gate. When the header is supplied with
    // a parseable integer, the storage::update_with_expected_version
    // path refuses the mutation with a 409 CONFLICT envelope carrying
    // both expected + current versions when the stored row has
    // drifted. When the header is absent or unparseable, the legacy
    // last-write-wins behaviour is preserved.
    let if_match_version: Option<i64> = headers
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            // Allow both bare integers and quoted ETag-style values
            // ("42" or 42).
            let trimmed = s.trim().trim_matches('"');
            trimmed.parse::<i64>().ok()
        });

    // v0.7.0 Wave-3 — Postgres-backed daemons take the SAL trait
    // dispatch path. The trait's `update` accepts an `UpdatePatch`
    // shape; map the `UpdateMemory` body into the trait shape and
    // delegate. The legacy SQLite path below threads federation,
    // embedder regen, audit, and governance hooks; Postgres takes
    // the simpler shape until those layers are also trait-routed.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let patch = crate::store::UpdatePatch {
            title: body.title.clone(),
            content: body.content.clone(),
            tier: body.tier.clone(),
            namespace: body.namespace.clone(),
            tags: body.tags.clone(),
            priority: body.priority,
            confidence: body.confidence,
            metadata: body.metadata.clone(),
            // v0.7.0 Provenance Gap 2 (#906) — thread source_uri patch.
            source_uri: body.source_uri.clone(),
            // v1.0.0 #1834 — thread valid_until patch (valid_from immutable).
            valid_until: body.valid_until.clone(),
            // v0.7.0 #1423 — thread expires_at patch. Pre-#1423 the
            // postgres branch built UpdatePatch without expires_at so
            // PUT /memories/{id} silently dropped body.expires_at on
            // a postgres-backed daemon. The sqlite branch never went
            // through UpdatePatch (it builds its own arg list against
            // db::update_with_expected_version) so this was a
            // postgres-only data drop.
            expires_at: body.expires_at.clone(),
            // v0.8.0 Pillar 2 (#1726) — thread the lifecycle transition
            // target so the postgres trait `update` enforces
            // `can_transition_to` (illegal edge → 409 via
            // `StoreError::InvalidTransition`). Already validated above.
            lifecycle_state: body
                .lifecycle_state
                .as_deref()
                .and_then(crate::models::LifecycleState::from_str),
        };
        // v0.7.0 ship-hardening (2026-05-19): resolve caller from
        // X-Agent-Id header so update() can authorize against the
        // memory's owner. Pre-fix this hardcoded "ai:http" which made
        // every update appear as if from the legacy daemon principal.
        let ctx = crate::handlers::parity::http_caller_ctx(&headers, None);
        // FBL-12 residual (#2378) — charge the storage-byte GROWTH of this
        // in-place update against the row OWNER's per-namespace storage cap
        // BEFORE the trait write lands, mirroring the sqlite branch below.
        // The pre-#2378 postgres branch skipped the quota entirely, so an
        // agent on a postgres daemon could grow each stored row toward
        // MAX_CONTENT_SIZE while `current_storage_bytes` reflected only the
        // store-time bytes — the per-agent storage-cap bypass FBL-12
        // documented, un-fixed on the pg network surface. Keyed on the
        // immutable row owner (`metadata.agent_id`) + effective namespace;
        // a legacy-unowned row (empty owner) is uncharged, mirroring the
        // create path. SAL new-operation recipe (prescribed precedent).
        let existing_for_quota = app.store.get(&ctx, &id).await.ok();
        let quota_charge: Option<(String, String, i64)> = match existing_for_quota.as_ref() {
            Some(existing) => {
                let owner = existing
                    .metadata
                    .get("agent_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                if owner.is_empty() {
                    None
                } else {
                    let eff_ns = patch
                        .namespace
                        .as_deref()
                        .unwrap_or(existing.namespace.as_str())
                        .to_string();
                    let new_meta = patch.metadata.as_ref().map_or_else(
                        || existing.metadata.clone(),
                        |m| crate::identity::preserve_update_provenance_keys(&existing.metadata, m),
                    );
                    let new_title = patch.title.as_deref().unwrap_or(existing.title.as_str());
                    let new_content = patch
                        .content
                        .as_deref()
                        .unwrap_or(existing.content.as_str());
                    let new_bytes = crate::quotas::coordination_payload_bytes(
                        &[new_title, new_content],
                        &[&new_meta],
                    );
                    let old_bytes = crate::quotas::coordination_payload_bytes(
                        &[&existing.title, &existing.content],
                        &[&existing.metadata],
                    );
                    match app
                        .store
                        .charge_update_growth(&ctx, &owner, &eff_ns, old_bytes, new_bytes)
                        .await
                    {
                        Ok(0) => None,
                        Ok(delta) => Some((owner, eff_ns, delta)),
                        // QuotaExceeded → 429 (full envelope) and every
                        // other charge error → its typed status, both via
                        // the shared `store_err_to_response` mapper.
                        Err(e) => return store_err_to_response(e),
                    }
                }
            }
            None => None,
        };
        // #1628 — honor `If-Match` on the postgres branch. Pre-fix the
        // parsed `if_match_version` was silently dropped here (the
        // trait `update` is last-write-wins), so stale writers clobbered
        // newer rows on postgres while sqlite refused them with 409.
        // Route through the version-gated inherent
        // `PostgresStore::update_with_expected_version` when a parseable
        // If-Match is present; absent/unparseable headers preserve the
        // legacy last-write-wins trait path, mirroring sqlite.
        let update_result: Result<(), crate::store::StoreError> = {
            #[cfg(feature = "sal-postgres")]
            {
                match (
                    if_match_version,
                    app.store
                        .as_any()
                        .downcast_ref::<crate::store::postgres::PostgresStore>(),
                ) {
                    (Some(expected), Some(pg)) => pg
                        .update_with_expected_version(&ctx, &id, patch, Some(expected))
                        .await
                        .map(|_new_version| ()),
                    _ => app.store.update(&ctx, &id, patch).await,
                }
            }
            #[cfg(not(feature = "sal-postgres"))]
            {
                app.store.update(&ctx, &id, patch).await
            }
        };
        return match update_result {
            Ok(()) => {
                // Re-fetch through the trait so the response payload
                // mirrors the legacy SQLite path's "return the updated
                // row" wire shape.
                let response_body = match app.store.get(&ctx, &id).await {
                    Ok(mem) => {
                        // #950 SECURITY-medium (Track A QC sweep,
                        // 2026-05-20) — fire subscription dispatch on
                        // the postgres update path. Pre-#950 only the
                        // `create_memory` postgres branch dispatched;
                        // every other memory-state-changing operation
                        // (update / delete / promote / link create /
                        // link delete / archive / restore / forget)
                        // silently skipped dispatch on postgres-backed
                        // daemons, breaking K7-style cross-namespace
                        // event-type registration end-to-end.
                        let agent_for_dispatch = mem
                            .metadata
                            .get("agent_id")
                            .and_then(|v| v.as_str())
                            .map(str::to_string);
                        let ns_for_dispatch = mem.namespace.clone();
                        super::dispatch_event_postgres(
                            &app,
                            crate::mcp::registry::tool_names::MEMORY_UPDATE,
                            &id,
                            &ns_for_dispatch,
                            agent_for_dispatch.as_deref(),
                            None,
                        )
                        .await;
                        Json(json!(mem)).into_response()
                    }
                    Err(_) => {
                        // Fallback wire shape — no `Memory` available to
                        // pull namespace/agent_id from. Dispatch is
                        // best-effort; without the namespace the event
                        // would have nowhere to anchor, so skip in this
                        // tail.
                        Json(json!({"updated": true, "id": id})).into_response()
                    }
                };
                response_body
            }
            Err(e) => {
                // FBL-12 residual (#2378) — refund the growth charge when
                // the write itself fails (e.g. a VersionConflict) so a
                // retry storm on a conflicting update cannot slowly inflate
                // the counter. Best-effort compensating decrement via the
                // inherent pg helper (downcast, mirroring the If-Match
                // path); the sqlite branch refunds via `refund_storage_only`.
                #[cfg(feature = "sal-postgres")]
                if let Some((ref owner, ref ns, delta)) = quota_charge
                    && let Some(pg) = app
                        .store
                        .as_any()
                        .downcast_ref::<crate::store::postgres::PostgresStore>()
                {
                    pg.refund_update_growth(owner, ns, delta).await;
                }
                #[cfg(not(feature = "sal-postgres"))]
                let _ = &quota_charge;
                // #1628 — map the version-gated conflict to the SAME
                // 409 CONFLICT envelope the sqlite branch returns (see
                // the `VersionConflict` downcast arm below): byte-equal
                // wire shape so callers retry identically on either
                // backend. The inherent pg helper surfaces the conflict
                // as `IntegrityFailed` whose detail carries the typed
                // message; reconstruct the typed `VersionConflict` so
                // the `error` string is produced by the same `Display`
                // impl the sqlite arm serialises.
                if let Some(expected) = if_match_version
                    && let crate::store::StoreError::IntegrityFailed { ref detail } = e
                    && let Some(current) = parse_pg_conflict_stored_version(detail)
                {
                    let vc = crate::storage::VersionConflict {
                        id: id.clone(),
                        expected,
                        current,
                    };
                    let error_text = vc.to_string();
                    return (
                        StatusCode::CONFLICT,
                        Json(json!({
                            "status": "conflict",
                            "id": vc.id,
                            "expected_version": vc.expected,
                            "current_version": vc.current,
                            "error": error_text,
                        })),
                    )
                        .into_response();
                }
                store_err_to_response(e)
            }
        };
    }

    // #930 SECURITY-high (Track A P9, 2026-05-20) — Full-Measure-A on
    // the sqlite UPDATE path. Resolve X-Agent-Id and refuse body /
    // header mismatch with HTTP 403. Mirrors the CREATE handler's
    // #874 / #901 / #907 gate. Pre-fix UPDATE silently accepted any
    // body.agent_id (including a forged one matching the row owner)
    // because the substrate `db::update_with_expected_version` takes
    // no caller-principal parameter.
    let caller = match crate::handlers::parity::resolve_caller_agent_id(
        body.agent_id.as_deref(),
        &headers,
        None,
    ) {
        Ok(c) => c,
        Err(err) if err.contains("agent_id_body_header_mismatch") => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": err,
                    "message": "body.agent_id must match the X-Agent-Id header"
                })),
            )
                .into_response();
        }
        Err(err) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": err}))).into_response();
        }
    };

    let lock = state.lock().await;
    // Resolve prefix if exact ID not found
    let resolved_id = match db::resolve_id(&lock.0, &id) {
        Ok(Some(mem)) => mem.id,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
        }
        Err(e) => {
            // #962 — typed downcast (was: msg.contains("ambiguous ID
            // prefix")). The substrate emits `StorageError::AmbiguousIdPrefix`
            // wrapped in anyhow; surface 400 with the typed Display body
            // (byte-identical to the legacy bail!() string).
            //
            // SAL-bypass intentional (#961): see `get_memory` above for
            // the rationale — `AmbiguousIdPrefix` is sqlite-legacy.
            if matches!(
                e.downcast_ref::<crate::storage::StorageError>(),
                Some(crate::storage::StorageError::AmbiguousIdPrefix { .. })
            ) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
            return crate::handlers::errors::handler_error_500(&e);
        }
    };
    // #930 — owner gate. Fetch the row's recorded `metadata.agent_id`
    // and refuse the update when the caller is neither the owner nor
    // the legacy "daemon" sentinel. 403 (not 404) here because the
    // caller has been authenticated by X-Agent-Id and has presented a
    // known id — the rejection IS the authorization signal, not an
    // existence-mask. The legacy "daemon" sentinel preserves backward
    // compatibility for boot-time / hook-driven updates that don't
    // route through X-Agent-Id (the audit chain captures the daemon-
    // origin path via signed_events).
    let existing_for_authz = db::get(&lock.0, &resolved_id).ok().flatten();
    if let Some(ref existing) = existing_for_authz {
        // #954 (Track A QC sweep, 2026-05-20) — delegated to the
        // canonical DRY helper. The previous inline check has been
        // replaced verbatim; the helper preserves the
        // legacy-unowned + daemon-exempt carve-outs and emits the
        // same 403 wire shape. Inbox carve-out disabled here: the
        // inbox target should NOT be able to mutate an out-of-band
        // sender's row via PUT.
        if let Some(resp) =
            crate::handlers::parity::require_caller_owns_memory(existing, &caller, false)
        {
            return resp;
        }
    }
    // Preserve existing agent_id when caller provides new metadata — provenance
    // is immutable after first write (see NHI design in crate::identity).
    let preserved_metadata = body.metadata.as_ref().map(|new_meta| {
        let existing_meta = existing_for_authz.as_ref().map_or_else(
            || serde_json::Value::Object(serde_json::Map::new()),
            |m| m.metadata.clone(),
        );
        crate::identity::preserve_update_provenance_keys(&existing_meta, new_meta)
    });
    // FBL-12 (v1.0.0 pre-ship 3x7) — charge the storage-byte GROWTH of
    // this in-place update against the row OWNER's per-namespace storage
    // cap BEFORE the write lands. Pre-fix the update funnels (this HTTP
    // PUT path + the MCP `memory_update` twin) skipped the quota entirely
    // — only `insert` charged it — so an agent could grow each stored row
    // to MAX_CONTENT_SIZE while its `current_storage_bytes` counter
    // reflected only the store-time bytes (an unbounded-growth bypass of
    // the per-agent storage cap). Keyed on the immutable row owner
    // (`metadata.agent_id`) + effective namespace; a legacy-unowned row
    // (empty owner) is uncharged, mirroring the create path.
    let quota_charge: Option<(String, String, i64)> = match existing_for_authz.as_ref() {
        Some(existing) => {
            let owner = existing
                .metadata
                .get("agent_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if owner.is_empty() {
                None
            } else {
                let eff_ns = body
                    .namespace
                    .as_deref()
                    .unwrap_or(existing.namespace.as_str())
                    .to_string();
                let new_meta = preserved_metadata
                    .clone()
                    .unwrap_or_else(|| existing.metadata.clone());
                let new_title = body.title.as_deref().unwrap_or(existing.title.as_str());
                let new_content = body.content.as_deref().unwrap_or(existing.content.as_str());
                let new_bytes = crate::quotas::coordination_payload_bytes(
                    &[new_title, new_content],
                    &[&new_meta],
                );
                let old_bytes = crate::quotas::coordination_payload_bytes(
                    &[&existing.title, &existing.content],
                    &[&existing.metadata],
                );
                match crate::quotas::charge_update_growth(
                    &lock.0, &owner, &eff_ns, old_bytes, new_bytes,
                ) {
                    Ok(0) => None,
                    Ok(delta) => Some((owner, eff_ns, delta)),
                    Err(crate::quotas::QuotaCheckError::Quota(qe)) => {
                        return (
                            StatusCode::TOO_MANY_REQUESTS,
                            Json(json!({
                                "code": crate::errors::error_codes::QUOTA_EXCEEDED,
                                "error": qe.to_string(),
                                "limit": qe.limit.as_str(),
                                "current": qe.current,
                                "max": qe.max,
                                "agent_id": qe.agent_id,
                            })),
                        )
                            .into_response();
                    }
                    Err(crate::quotas::QuotaCheckError::Sql(se)) => {
                        tracing::error!("update_memory: quota substrate error: {se}");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": crate::errors::msg::QUOTA_CHECK_FAILED})),
                        )
                            .into_response();
                    }
                }
            }
        }
        None => None,
    };
    match db::update_with_expected_version(
        &lock.0,
        &resolved_id,
        body.title.as_deref(),
        body.content.as_deref(),
        body.tier.as_ref(),
        body.namespace.as_deref(),
        body.tags.as_ref(),
        body.priority,
        body.confidence,
        body.expires_at.as_deref(),
        preserved_metadata.as_ref(),
        body.source_uri.as_deref(),
        if_match_version,
        // v1.0.0 #1834 — opt-in valid_until patch (valid_from immutable).
        body.valid_until.as_deref(),
    ) {
        Ok((true, _)) => {
            // v0.8.0 Pillar 2 (#1726) — apply an optional lifecycle
            // transition through the self-validating storage primitive. An
            // illegal edge surfaces as a typed `InvalidTransition` → 409
            // CONFLICT (byte-parity error detail with the postgres branch's
            // `StoreError::InvalidTransition`); a request equal to the stored
            // state is an idempotent no-op. `body.lifecycle_state` was already
            // shape-validated by `validate_update` above.
            if let Some(target) = body
                .lifecycle_state
                .as_deref()
                .and_then(crate::models::LifecycleState::from_str)
                && let Err(e) = db::set_lifecycle_state(&lock.0, &resolved_id, target)
            {
                if let Some(it) = e.downcast_ref::<crate::storage::InvalidTransition>() {
                    return (
                        StatusCode::CONFLICT,
                        Json(json!({
                            "status": "conflict",
                            "id": resolved_id,
                            "error": it.to_string(),
                        })),
                    )
                        .into_response();
                }
                return crate::handlers::errors::handler_error_500(&e);
            }
            let mem = db::get(&lock.0, &resolved_id).ok().flatten();
            // Issue #219: regenerate the embedding when the searchable text
            // (title/content) changed. Without this, the semantic index keeps
            // pointing at the old vector and stale semantic recall results
            // linger even after the row is updated.
            let content_changed = body.title.is_some() || body.content.is_some();
            let mut lock_opt = Some(lock);
            if content_changed && let Some(ref m) = mem {
                let text = crate::embeddings::embedding_document(&m.title, &m.content);
                if let Some(emb) = app.embedder.as_ref().as_ref() {
                    match emb.embed(&text) {
                        Ok(vec) => {
                            if let Some(ref l) = lock_opt
                                && let Err(e) = db::set_embedding(
                                    &l.0,
                                    &resolved_id,
                                    &vec,
                                    &emb.space_fingerprint(),
                                )
                            {
                                tracing::warn!(
                                    "failed to refresh embedding for {resolved_id}: {e}"
                                );
                            }
                            // Drop DB lock before touching vector index.
                            lock_opt.take();
                            let mut idx_lock = app.vector_index.lock().await;
                            if let Some(idx) = idx_lock.as_mut() {
                                idx.remove(&resolved_id);
                                idx.insert(resolved_id.clone(), vec);
                            }
                        }
                        Err(e) => tracing::warn!("embedding regeneration failed: {e}"),
                    }
                }
            }
            // Drop the DB lock before fanning out — peers POST back to
            // our sync_push so we'd deadlock if we held it.
            drop(lock_opt);
            // v0.6.0.1: fan out the mutation to peers so remote readers
            // see the update, not the pre-update row. insert_if_newer on
            // peers sees a newer updated_at and applies.
            if let (Some(fed), Some(m)) = (app.federation.as_ref(), mem.as_ref())
                && let Ok(tracker) = crate::federation::broadcast_store_quorum(fed, m).await
                && let Err(err) = crate::federation::finalise_quorum(&tracker)
            {
                // #869 — typed 503 envelope via the shared helper.
                let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                return super::under_replicated_response(&payload);
            }
            Json(json!(mem)).into_response()
        }
        Ok((false, _)) => {
            // FBL-12 — refund the growth charge when the row vanished
            // between the charge and the write (the growth never landed).
            if let Some((ref owner, ref ns, delta)) = quota_charge {
                let _ = crate::quotas::refund_storage_only(&lock.0, owner, ns, delta);
            }
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
        }
        Err(e) => {
            // FBL-12 — refund the growth charge when the write itself
            // fails (e.g. a VersionConflict) so a retry storm on a
            // conflicting update cannot slowly inflate the counter.
            if let Some((ref owner, ref ns, delta)) = quota_charge {
                let _ = crate::quotas::refund_storage_only(&lock.0, owner, ns, delta);
            }
            // v0.7.0 Provenance Gap 1 (#884) — typed VersionConflict
            // surfaces as 409 with a structured envelope naming both
            // expected + current versions so callers can re-read and
            // retry with the fresh version.
            //
            // SAL-bypass intentional (#961): the SAL `StoreError`
            // enum has a `Conflict { id }` variant but does not carry
            // the typed (expected, current) version pair the
            // `If-Match` retry-shape needs. The legacy
            // `db::update_with_expected_version` is the canonical
            // origin of the typed `VersionConflict`; downcasting here
            // preserves the structured retry envelope. The postgres
            // branch above routes through `app.store.update` which
            // surfaces `StoreError::Conflict` via `store_err_to_response`.
            if let Some(vc) = e.downcast_ref::<crate::storage::VersionConflict>() {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "status": "conflict",
                        "id": vc.id,
                        "expected_version": vc.expected,
                        "current_version": vc.current,
                        "error": e.to_string(),
                    })),
                )
                    .into_response();
            }
            let msg = e.to_string();
            if msg.contains("already exists in namespace") {
                return (StatusCode::CONFLICT, Json(json!({"error": msg}))).into_response();
            }
            crate::handlers::errors::handler_error_500(&e)
        }
    }
}

#[allow(clippy::too_many_lines)]
pub async fn delete_memory(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let state = app.db.clone();
    if let Err(e) = validate::validate_id(&id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }

    // #2044 (#2032-A / H1 IDOR) — per-agent-key identity gate before the
    // destructive delete.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "delete_memory",
    ) {
        return resp;
    }

    // #1924 (CWE-288) — consult the PRE-DELETE enforcement gate before the
    // destructive write, so `enforce_mode = enforce` + required `pre_delete`
    // with no hook DENIES (503) on the HTTP surface as it does on MCP.
    // #2390 (N9) — the deleted row's namespace is the in-flight namespace; the
    // payload used to be `{"id": id}` with no namespace at all, so every
    // namespace-scoped `pre_delete` hook was silently skipped. Resolved through
    // the SAL trait (sqlite + postgres parity), and only when the gate is armed.
    let delete_namespaces =
        crate::handlers::create::resolve_pre_event_namespaces(&app, &headers, &[id.clone()]).await;
    if let Some(resp) = crate::handlers::create::http_pre_event_gate(
        crate::hooks::HookEvent::PreDelete,
        delete_namespaces,
        json!({ "id": id }),
    ) {
        return resp;
    }

    // #913 (security-medium / SOC2, 2026-05-19) — admin/destructive
    // action audit. Memory delete is the canonical destructive operation;
    // the forensic-chain entry MUST land before the storage write so the
    // audit trail captures intent even when the downstream delete errors.
    // The existing `audit::emit(AuditAction::Delete)` further down writes
    // the SIEM-shaped enterprise audit row AFTER the delete commits;
    // these two channels are intentionally complementary.
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    let caller_for_forensic = crate::identity::resolve_http_agent_id(None, header_agent_id)
        .unwrap_or_else(|_| sentinels::ANONYMOUS_INVALID.to_string());
    crate::governance::audit::record_decision(
        &caller_for_forensic,
        "allow",
        crate::mcp::registry::tool_names::MEMORY_DELETE,
        "",
        json!({ "id": &id }),
    );

    // v0.7.0 Wave-3 — Postgres-backed daemons dispatch through the
    // SAL trait. The legacy delete path threads governance, audit,
    // and federation fanout through the SQLite mutex; those layers
    // (governance owner-walk, audit chain, quorum broadcast) are
    // SQLite-bound today, so the postgres-eligible delete is the
    // simpler "delete by id" surface the SAL trait already provides.
    // Operators who need the full governance + audit + quorum bundle
    // on Postgres should follow the migration plan in
    // `docs/postgres-age-guide.md`.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // Resolve the target memory before delete so the audit emit
        // captures namespace + title metadata (Phase 9 — audit emit
        // parity on postgres).
        let header_agent_id = headers
            .get(crate::HEADER_AGENT_ID)
            .and_then(|v| v.to_str().ok());
        let agent_id = crate::identity::resolve_http_agent_id(None, header_agent_id)
            .unwrap_or_else(|_| sentinels::AI_HTTP.to_string());
        // v0.9.0 G10.1 (#1827) — edge-parse the optional
        // `X-AI-Memory-Capability` header ONCE into the caller context;
        // inert unless `[capabilities].enabled`.
        let ctx = crate::store::CallerContext::for_agent(agent_id.clone()).with_capability(
            crate::handlers::capability_from_headers(&headers, &agent_id),
        );
        let target = app.store.get(&ctx, &id).await.ok();

        // F-A2A1.2 (#700) — governance enforcement on the postgres delete
        // path. Mirrors the sqlite gate at line ~1913 below: a denied
        // delete returns 403; an `Approve`-level policy queues a pending
        // action and returns 202 Accepted. Without this gate the postgres
        // branch silently bypassed the namespace standard's `delete=`
        // rule, allowing any caller to delete a row in a governed
        // namespace. Closes the postgres half of the same surface S34/S60
        // exercise on the write path.
        if let Some(ref mem) = target {
            use crate::models::GovernanceDecision;
            let memory_owner = mem
                .metadata
                .get("agent_id")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let payload = json!({"id": mem.id, "title": mem.title});
            // #2356 (W1A6-03) — `pre_governance_decision` presence consult
            // BEFORE the governance decision dispatches (postgres branch).
            if let Some(resp) = super::create::http_pre_governance_decision_gate(
                &mem.namespace,
                "delete",
                &agent_id,
                Some(&mem.id),
            ) {
                return resp;
            }
            match app
                .store
                .enforce_governance_action(
                    crate::store::GovernedAction::Delete,
                    &mem.namespace,
                    &agent_id,
                    Some(&mem.id),
                    memory_owner.as_deref(),
                    &payload,
                    ctx.capability.as_ref(),
                )
                .await
            {
                Ok(GovernanceDecision::Allow) => {}
                Ok(GovernanceDecision::Deny(refusal)) => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"error": crate::governance::deny_message("delete", crate::governance::DenyGate::Governance, &refusal.reason)})),
                    )
                        .into_response();
                }
                Ok(GovernanceDecision::Pending(pending_id)) => {
                    return (
                        StatusCode::ACCEPTED,
                        Json(json!({
                            "status": "pending",
                            (field_names::PENDING_ID): pending_id,
                            "reason": crate::errors::msg::GOVERNANCE_REQUIRES_APPROVAL,
                            "action": "delete",
                            "memory_id": mem.id,
                            (field_names::STORAGE_BACKEND): "postgres",
                        })),
                    )
                        .into_response();
                }
                Err(e) => return store_err_to_response(e),
            }
        }

        return match app.store.delete(&ctx, &id).await {
            Ok(()) => {
                if crate::audit::is_enabled() {
                    let (namespace, title, tier) = target
                        .as_ref()
                        .map(|m| {
                            (
                                m.namespace.clone(),
                                Some(m.title.clone()),
                                Some(m.tier.to_string()),
                            )
                        })
                        .unwrap_or_else(|| (String::new(), None, None));
                    crate::audit::emit(crate::audit::EventBuilder::new(
                        crate::audit::AuditAction::Delete,
                        crate::audit::actor(
                            &agent_id,
                            crate::audit::synthesis_sources::HTTP_HEADER,
                            None,
                        ),
                        crate::audit::target_memory(id.clone(), namespace, title, tier, None),
                    ));
                }
                // #950 SECURITY-medium (Track A QC sweep, 2026-05-20) —
                // fire subscription dispatch on the postgres delete
                // path. Best-effort: when the target was missing we
                // skip dispatch (no namespace anchor); otherwise emit
                // the canonical `memory_delete` event so
                // K7-style cross-namespace event subscribers get the
                // delete notification on postgres-backed daemons.
                if let Some(ref mem) = target {
                    let mem_owner = mem
                        .metadata
                        .get("agent_id")
                        .and_then(|v| v.as_str())
                        .map(str::to_string);
                    super::dispatch_event_postgres(
                        &app,
                        crate::mcp::registry::tool_names::MEMORY_DELETE,
                        &id,
                        &mem.namespace,
                        mem_owner.as_deref(),
                        None,
                    )
                    .await;
                }
                (StatusCode::OK, Json(json!({"deleted": true, "id": id}))).into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = state.lock().await;
    // Resolve the target memory so governance has owner context.
    let target = match db::resolve_id(&lock.0, &id) {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
        }
        Err(e) => {
            // #962 — typed downcast (was: msg.contains("ambiguous ID
            // prefix")). The substrate emits `StorageError::AmbiguousIdPrefix`
            // wrapped in anyhow; surface 400 with the typed Display body
            // (byte-identical to the legacy bail!() string).
            //
            // SAL-bypass intentional (#961): see `get_memory` for the
            // canonical rationale — `AmbiguousIdPrefix` is sqlite-legacy.
            if matches!(
                e.downcast_ref::<crate::storage::StorageError>(),
                Some(crate::storage::StorageError::AmbiguousIdPrefix { .. })
            ) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
            return crate::handlers::errors::handler_error_500(&e);
        }
    };

    // Task 1.9: governance enforcement (delete-side).
    {
        use crate::models::{GovernanceDecision, GovernedAction};
        let header_agent_id = headers
            .get(crate::HEADER_AGENT_ID)
            .and_then(|v| v.to_str().ok());
        let agent_id = match crate::identity::resolve_http_agent_id(None, header_agent_id) {
            Ok(a) => a,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": crate::errors::msg::invalid("agent_id", e)})),
                )
                    .into_response();
            }
        };
        let mem_owner = target
            .metadata
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        // #937 SECURITY-high (Track A QC sweep, 2026-05-20) — caller-
        // vs-row-owner gate on DELETE. Pre-fix any caller could delete
        // any memory in the unconfigured-governance default posture
        // because `enforce_governance` returns Allow when no policy is
        // set. Identity-level check is independent of governance —
        // even without a policy, a non-owner cannot delete someone
        // else's row. Mirrors the gate added in #930 for UPDATE +
        // PROMOTE (commit 49739bb46) and #938 / #940 / #939+#941.
        //
        // #954 (Track A QC sweep, 2026-05-20) — delegated to the
        // canonical DRY helper. Inbox carve-out enabled: the
        // recipient of an inbox message (`metadata.target_agent_id`)
        // IS permitted to delete that message after consuming it,
        // per the pre-#954 inline behaviour.
        if let Some(resp) =
            crate::handlers::parity::require_caller_owns_memory(&target, &agent_id, true)
        {
            return resp;
        }
        let payload = json!({"id": target.id, "title": target.title});
        // v0.9.0 G10.1 (#1827) — edge-parse the optional
        // `X-AI-Memory-Capability` header ONCE; inert unless
        // `[capabilities].enabled`.
        let capability = crate::handlers::capability_from_headers(&headers, &agent_id);
        // #2356 (W1A6-03) — `pre_governance_decision` presence consult
        // BEFORE the governance decision dispatches (sqlite branch).
        if let Some(resp) = super::create::http_pre_governance_decision_gate(
            &target.namespace,
            "delete",
            &agent_id,
            Some(&target.id),
        ) {
            return resp;
        }
        match db::enforce_governance(
            &lock.0,
            GovernedAction::Delete,
            &target.namespace,
            &agent_id,
            Some(&target.id),
            mem_owner.as_deref(),
            &payload,
            capability.as_ref(),
        ) {
            Ok(GovernanceDecision::Allow) => {}
            Ok(GovernanceDecision::Deny(refusal)) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": crate::governance::deny_message("delete", crate::governance::DenyGate::Governance, &refusal.reason)})),
                )
                    .into_response();
            }
            Ok(GovernanceDecision::Pending(pending_id)) => {
                // v0.6.2 (S34): fan out the new pending delete row so peers
                // see consistent governance queue state.
                let pending_row = db::get_pending_action(&lock.0, &pending_id).ok().flatten();
                // v0.7.0 K4 — surface the new row through the
                // subscription dispatcher (`approval_requested`). See
                // the store-side companion call for rationale.
                crate::subscriptions::dispatch_approval_requested(&lock.0, &pending_id, &lock.1);
                let target_id = target.id.clone();
                drop(lock);
                if let (Some(pa), Some(fed)) = (pending_row.as_ref(), app.federation.as_ref()) {
                    match crate::federation::broadcast_pending_quorum(fed, pa).await {
                        Ok(tracker) => {
                            if let Err(err) = crate::federation::finalise_quorum(&tracker) {
                                // #869 — typed 503 envelope via the shared helper.
                                let payload =
                                    crate::federation::QuorumNotMetPayload::from_err(&err);
                                return super::under_replicated_response(&payload);
                            }
                        }
                        Err(err) => {
                            let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                            return super::under_replicated_response(&payload);
                        }
                    }
                }
                return (
                    StatusCode::ACCEPTED,
                    Json(json!({
                        "status": "pending",
                        (field_names::PENDING_ID): pending_id,
                        "reason": crate::errors::msg::GOVERNANCE_REQUIRES_APPROVAL,
                        "action": "delete",
                        "memory_id": target_id,
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                return crate::handlers::errors::governance_error_500(&e);
            }
        }
    }

    let delete_outcome = db::delete(&lock.0, &target.id);
    // v0.6.4-017 — G9 HTTP webhook parity. Fire `memory_delete` after
    // the row is gone (mirrors the MCP pattern at mcp.rs:2227). Snapshot
    // fields come from the pre-delete `target`. Best-effort,
    // fire-and-forget: dispatch does a quick subscriber lookup on the
    // current connection and spawns a thread for the HTTP POST so the
    // response is never blocked. Held inside the lock so the subscriber
    // list query has a connection — release happens after.
    if matches!(delete_outcome, Ok(true)) {
        let details = serde_json::to_value(crate::subscriptions::DeleteEventDetails {
            title: target.title.clone(),
            tier: target.tier.to_string(),
        })
        .ok();
        let owner_aid = target
            .metadata
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        crate::subscriptions::dispatch_event_with_details(
            &lock.0,
            crate::mcp::registry::tool_names::MEMORY_DELETE,
            &target.id,
            &target.namespace,
            owner_aid.as_deref(),
            &lock.1,
            details,
        );
    }
    // Drop DB lock before fanning out — peers POST back to our
    // sync_push and we'd deadlock on the shared Mutex if we held it.
    drop(lock);
    match delete_outcome {
        Ok(true) => {
            // PR-5 (issue #487): security audit trail for HTTP delete.
            let owner = target
                .metadata
                .get("agent_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    headers
                        .get(crate::HEADER_AGENT_ID)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("anonymous")
                        .to_string()
                });
            crate::audit::emit(crate::audit::EventBuilder::new(
                crate::audit::AuditAction::Delete,
                crate::audit::actor(owner, crate::audit::synthesis_sources::HTTP_HEADER, None),
                crate::audit::target_memory(
                    target.id.clone(),
                    target.namespace.clone(),
                    Some(target.title.clone()),
                    Some(target.tier.to_string()),
                    None,
                ),
            ));
            // v0.6.0.1: propagate tombstone via sync_push.deletions.
            if let Some(fed) = app.federation.as_ref()
                && let Ok(tracker) =
                    crate::federation::broadcast_delete_quorum(fed, &target.id).await
                && let Err(err) = crate::federation::finalise_quorum(&tracker)
            {
                // #869 — typed 503 envelope via the shared helper.
                let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                return super::under_replicated_response(&payload);
            }
            Json(json!({"deleted": true})).into_response()
        }
        _ => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

#[allow(clippy::too_many_lines)]
pub async fn promote_memory(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let state = app.db.clone();
    if let Err(e) = validate::validate_id(&id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }
    // #2044 (#2032-A / H1 IDOR) — per-agent-key identity gate.
    if let Some(resp) = crate::handlers::identity_binding::enforce_idor_identity(
        &app.enrolled_agent_keys,
        app.http_identity_mode,
        &headers,
        "promote_memory",
    ) {
        return resp;
    }
    // #1924 (CWE-288) — consult the PRE-PROMOTE enforcement gate before the
    // tier-promotion write (HTTP parity with the MCP gate).
    // #2390 (N9) — the promoted row's namespace (see the `pre_delete` note).
    let promote_namespaces =
        crate::handlers::create::resolve_pre_event_namespaces(&app, &headers, &[id.clone()]).await;
    if let Some(resp) = crate::handlers::create::http_pre_event_gate(
        crate::hooks::HookEvent::PrePromote,
        promote_namespaces,
        json!({ "id": id }),
    ) {
        return resp;
    }
    // #1623 — optional JSON body `{"target_tier": "mid"|"long"}`,
    // closing the MCP/HTTP parity gap (#831 added the param on MCP;
    // the HTTP route read no body and silently jumped to long even
    // when a caller supplied one). Empty body preserves the
    // historical highest-reachable-tier default. Validation mirrors
    // the MCP handler's wording.
    let target_tier = if body.is_empty() {
        Tier::Long
    } else {
        let parsed: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("invalid promote body JSON: {e}")})),
                )
                    .into_response();
            }
        };
        match parsed.get("target_tier").and_then(|v| v.as_str()) {
            None => Tier::Long,
            Some("short") => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "target_tier 'short' is not a valid promote target (would be a downgrade)"})),
                )
                    .into_response();
            }
            Some(other) => match Tier::from_str(other) {
                Some(t) => t,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": format!("target_tier must be one of 'mid' or 'long' (got '{other}')")})),
                    )
                        .into_response();
                }
            },
        }
    };

    // v0.7.0 Wave-3 Continuation 5 (state-flake / S16+S49) — postgres-
    // backed daemons resolve the memory through the SAL trait so a
    // freshly-stored row promotes correctly across daemon restart.
    // Without this branch the handler reaches into the scratch SQLite
    // db (`:memory:` in test, stale on droplet after disposable DB
    // reset) and returns 404 — the documented Wave 4 R2 flake.
    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        let header_agent_id = headers
            .get(crate::HEADER_AGENT_ID)
            .and_then(|v| v.to_str().ok());
        let agent_id = match crate::identity::resolve_http_agent_id(None, header_agent_id) {
            Ok(a) => a,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": crate::errors::msg::invalid("agent_id", e)})),
                )
                    .into_response();
            }
        };
        // v0.9.0 G10.1 (#1827) — edge-parse the optional
        // `X-AI-Memory-Capability` header ONCE into the caller context;
        // inert unless `[capabilities].enabled`.
        let ctx = crate::store::CallerContext::for_agent(&agent_id).with_capability(
            crate::handlers::capability_from_headers(&headers, &agent_id),
        );
        // F-A2A1.4 (#700, S16/S49) — bounded retry on NotFound. A
        // freshly-stored row that travelled through a read replica or
        // is still settling in WAL flush can briefly return
        // NotFound from the SAL `get`. The 22-failure triage (memory
        // 9ffaa55d) classified this as Bucket-A: the row exists, the
        // promote handler just races the visibility window. Retry up
        // to 4 times with bounded backoff (5/10/15/20 ms — 50 ms
        // total) before surfacing 404 — well below the 2 s daemon
        // p99 SLO and dwarfed by typical store-side replication
        // latency. See `get_with_visibility_retry` for the helper.
        let target =
            match super::http::get_with_visibility_retry(app.store.as_ref(), &ctx, &id).await {
                Ok(m) => m,
                Err(crate::store::StoreError::NotFound { .. }) => {
                    return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})))
                        .into_response();
                }
                Err(e) => return store_err_to_response(e),
            };

        // F-A2A1.2 (#700) — governance enforcement on the postgres promote
        // path. Mirrors the sqlite gate at line ~2169 below: an `owner`
        // policy on the namespace standard denies a non-owner promote
        // (403); an `approve`-level policy queues a pending action (202).
        // The postgres branch previously skipped this gate, letting any
        // caller promote a row to `long` tier regardless of namespace
        // governance.
        {
            use crate::models::GovernanceDecision;
            let memory_owner = target
                .metadata
                .get("agent_id")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let payload = json!({"id": target.id});
            // #2356 (W1A6-03) — `pre_governance_decision` presence consult
            // BEFORE the governance decision dispatches (postgres branch).
            if let Some(resp) = super::create::http_pre_governance_decision_gate(
                &target.namespace,
                "promote",
                &agent_id,
                Some(&target.id),
            ) {
                return resp;
            }
            match app
                .store
                .enforce_governance_action(
                    crate::store::GovernedAction::Promote,
                    &target.namespace,
                    &agent_id,
                    Some(&target.id),
                    memory_owner.as_deref(),
                    &payload,
                    ctx.capability.as_ref(),
                )
                .await
            {
                Ok(GovernanceDecision::Allow) => {}
                Ok(GovernanceDecision::Deny(refusal)) => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({"error": crate::governance::deny_message("promote", crate::governance::DenyGate::Governance, &refusal.reason)})),
                    )
                        .into_response();
                }
                Ok(GovernanceDecision::Pending(pending_id)) => {
                    return (
                        StatusCode::ACCEPTED,
                        Json(json!({
                            "status": "pending",
                            (field_names::PENDING_ID): pending_id,
                            "reason": crate::errors::msg::GOVERNANCE_REQUIRES_APPROVAL,
                            "action": "promote",
                            "memory_id": target.id,
                            (field_names::STORAGE_BACKEND): "postgres",
                        })),
                    )
                        .into_response();
                }
                Err(e) => return store_err_to_response(e),
            }
        }

        let patch = crate::store::UpdatePatch {
            tier: Some(target_tier),
            ..Default::default()
        };
        return match app.store.update(&ctx, &target.id, patch).await {
            Ok(()) => {
                // F-A2A1.4 (#700, S16/S49) — post-promote federation
                // fanout on the postgres branch. Mirrors the sqlite
                // path at lines ~2406-2417: after a successful local
                // tier-update, re-fetch the row to capture the new
                // tier + cleared expiry (#1626 — the trait update's
                // tier→long arm now clears `expires_at` in SQL, so
                // this re-fetch genuinely observes the clear) and
                // broadcast via
                // `broadcast_store_quorum` so peers' projections of
                // the same memory inherit the tier ladder. Without
                // this, a `notify` recipient on peer-B still sees the
                // row at its pre-promote tier and a recall against
                // `tier=long` on peer-B silently misses it.
                //
                // Failure handling: fanout failures surface as 503
                // with `Retry-After: 2` mirroring sqlite. The local
                // tier update has already committed — per ADR-0001
                // we do NOT roll back the local commit on quorum
                // failure; the sync daemon's eventual-consistency
                // loop catches stragglers.
                if let Some(fed) = app.federation.as_ref() {
                    let promoted_mem = match app.store.get(&ctx, &target.id).await {
                        Ok(m) => Some(m),
                        Err(_) => None,
                    };
                    if let Some(ref m) = promoted_mem {
                        match crate::federation::broadcast_store_quorum(fed, m).await {
                            Ok(tracker) => {
                                if let Err(err) = crate::federation::finalise_quorum(&tracker) {
                                    // #869 — typed 503 envelope via the shared helper.
                                    let payload =
                                        crate::federation::QuorumNotMetPayload::from_err(&err);
                                    return super::under_replicated_response(&payload);
                                }
                            }
                            Err(err) => {
                                let payload =
                                    crate::federation::QuorumNotMetPayload::from_err(&err);
                                return super::under_replicated_response(&payload);
                            }
                        }
                    }
                }
                // #950 SECURITY-medium (Track A QC sweep, 2026-05-20)
                // — fire subscription dispatch on the postgres promote
                // path. Mirrors `memory_promote` on the sqlite branch.
                let mem_owner = target
                    .metadata
                    .get("agent_id")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                super::dispatch_event_postgres(
                    &app,
                    crate::mcp::registry::tool_names::MEMORY_PROMOTE,
                    &target.id,
                    &target.namespace,
                    mem_owner.as_deref(),
                    None,
                )
                .await;
                Json(json!({
                    "promoted": true,
                    "id": target.id,
                    "tier": Tier::Long.as_str(),
                    (field_names::STORAGE_BACKEND): "postgres",
                }))
                .into_response()
            }
            Err(crate::store::StoreError::NotFound { .. }) => {
                (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
            }
            Err(e) => store_err_to_response(e),
        };
    }

    let lock = state.lock().await;
    // Resolve prefix if exact ID not found — capture full memory for governance.
    let target = match db::resolve_id(&lock.0, &id) {
        Ok(Some(mem)) => mem,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response();
        }
        Err(e) => {
            // #962 — typed downcast (was: msg.contains("ambiguous ID
            // prefix")). The substrate emits `StorageError::AmbiguousIdPrefix`
            // wrapped in anyhow; surface 400 with the typed Display body
            // (byte-identical to the legacy bail!() string).
            //
            // SAL-bypass intentional (#961): see `get_memory` for the
            // canonical rationale — `AmbiguousIdPrefix` is sqlite-legacy.
            if matches!(
                e.downcast_ref::<crate::storage::StorageError>(),
                Some(crate::storage::StorageError::AmbiguousIdPrefix { .. })
            ) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
            return crate::handlers::errors::handler_error_500(&e);
        }
    };
    // Task 1.9: governance enforcement (promote-side).
    {
        use crate::models::{GovernanceDecision, GovernedAction};
        let header_agent_id = headers
            .get(crate::HEADER_AGENT_ID)
            .and_then(|v| v.to_str().ok());
        let agent_id = match crate::identity::resolve_http_agent_id(None, header_agent_id) {
            Ok(a) => a,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": crate::errors::msg::invalid("agent_id", e)})),
                )
                    .into_response();
            }
        };
        let mem_owner = target
            .metadata
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        // #930 SECURITY-high (Track A P9, 2026-05-20) — caller-owner
        // gate on PROMOTE. Pre-fix Bob could promote Alice's row from
        // `short`→`long` (changing the TTL semantics on her row) when
        // no namespace governance standard was set, because
        // enforce_governance defaults to Allow on absent policy. The
        // ownership check is identity-level, not governance-level —
        // even without a namespace policy, a non-owner cannot promote
        // someone else's row. Mirrors the UPDATE gate added in the
        // same campaign.
        //
        // #954 (Track A QC sweep, 2026-05-20) — delegated to the
        // canonical DRY helper at `parity::require_caller_owns_memory`.
        // Inbox carve-out disabled: the inbox target should not be
        // able to promote / TTL-change the sender's row.
        if let Some(resp) =
            crate::handlers::parity::require_caller_owns_memory(&target, &agent_id, false)
        {
            return resp;
        }
        let payload = json!({"id": target.id});
        // v0.9.0 G10.1 (#1827) — edge-parse the optional
        // `X-AI-Memory-Capability` header ONCE; inert unless
        // `[capabilities].enabled`.
        let capability = crate::handlers::capability_from_headers(&headers, &agent_id);
        // #2356 (W1A6-03) — `pre_governance_decision` presence consult
        // BEFORE the governance decision dispatches (sqlite branch).
        if let Some(resp) = super::create::http_pre_governance_decision_gate(
            &target.namespace,
            "promote",
            &agent_id,
            Some(&target.id),
        ) {
            return resp;
        }
        match db::enforce_governance(
            &lock.0,
            GovernedAction::Promote,
            &target.namespace,
            &agent_id,
            Some(&target.id),
            mem_owner.as_deref(),
            &payload,
            capability.as_ref(),
        ) {
            Ok(GovernanceDecision::Allow) => {}
            Ok(GovernanceDecision::Deny(refusal)) => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": crate::governance::deny_message("promote", crate::governance::DenyGate::Governance, &refusal.reason)})),
                )
                    .into_response();
            }
            Ok(GovernanceDecision::Pending(pending_id)) => {
                // v0.6.2 (S34): fan out the new pending promote row too.
                let pending_row = db::get_pending_action(&lock.0, &pending_id).ok().flatten();
                // v0.7.0 K4 — surface the new row through the
                // subscription dispatcher (`approval_requested`). See
                // the store-side companion call for rationale.
                crate::subscriptions::dispatch_approval_requested(&lock.0, &pending_id, &lock.1);
                let target_id = target.id.clone();
                drop(lock);
                if let (Some(pa), Some(fed)) = (pending_row.as_ref(), app.federation.as_ref()) {
                    match crate::federation::broadcast_pending_quorum(fed, pa).await {
                        Ok(tracker) => {
                            if let Err(err) = crate::federation::finalise_quorum(&tracker) {
                                // #869 — typed 503 envelope via the shared helper.
                                let payload =
                                    crate::federation::QuorumNotMetPayload::from_err(&err);
                                return super::under_replicated_response(&payload);
                            }
                        }
                        Err(err) => {
                            let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                            return super::under_replicated_response(&payload);
                        }
                    }
                }
                return (
                    StatusCode::ACCEPTED,
                    Json(json!({
                        "status": "pending",
                        (field_names::PENDING_ID): pending_id,
                        "reason": crate::errors::msg::GOVERNANCE_REQUIRES_APPROVAL,
                        "action": "promote",
                        "memory_id": target_id,
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                return crate::handlers::errors::governance_error_500(&e);
            }
        }
    }

    let resolved_id = target.id.clone();
    match db::update(
        &lock.0,
        &resolved_id,
        None,
        None,
        Some(&target_tier),
        None,
        None,
        None,
        None,
        None,
        None,
    ) {
        Ok((true, _)) => {
            // #1623 — only a LONG landing clears expiry (long is
            // permanent); a mid landing keeps the row's live 7-day
            // TTL, matching the MCP handler's semantics.
            if matches!(target_tier, Tier::Long) {
                if let Err(e) = lock.0.execute(
                    "UPDATE memories SET expires_at = NULL WHERE id = ?1",
                    rusqlite::params![resolved_id],
                ) {
                    tracing::error!("promote clear expiry failed: {e}");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": crate::errors::msg::INTERNAL_SERVER_ERROR})),
                    )
                        .into_response();
                }
            }
            // v0.6.0.1: fan out the promoted memory so peers pick up the
            // new tier + cleared expiry via insert_if_newer's newer-wins merge.
            let promoted_mem = db::get(&lock.0, &resolved_id).ok().flatten();
            // v0.6.4-017 — G9 HTTP webhook parity. Fire `memory_promote`
            // (tier mode — HTTP only does tier promotion, MCP also does
            // vertical). Mirrors mcp.rs:2369 pattern.
            let owner_aid = target
                .metadata
                .get("agent_id")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let details = serde_json::to_value(crate::subscriptions::PromoteEventDetails {
                mode: "tier".to_string(),
                tier: Some(target_tier.as_str().to_string()),
                to_namespace: None,
                clone_id: None,
            })
            .ok();
            crate::subscriptions::dispatch_event_with_details(
                &lock.0,
                crate::mcp::registry::tool_names::MEMORY_PROMOTE,
                &resolved_id,
                &target.namespace,
                owner_aid.as_deref(),
                &lock.1,
                details,
            );
            drop(lock);
            if let (Some(fed), Some(m)) = (app.federation.as_ref(), promoted_mem.as_ref())
                && let Ok(tracker) = crate::federation::broadcast_store_quorum(fed, m).await
                && let Err(err) = crate::federation::finalise_quorum(&tracker)
            {
                // #869 — typed 503 envelope via the shared helper.
                let payload = crate::federation::QuorumNotMetPayload::from_err(&err);
                return super::under_replicated_response(&payload);
            }
            Json(json!({"promoted": true, "id": resolved_id, "tier": Tier::Long.as_str()}))
                .into_response()
        }
        Ok((false, _)) => {
            (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response()
        }
        Err(e) => crate::handlers::errors::handler_error_500(&e),
    }
}
