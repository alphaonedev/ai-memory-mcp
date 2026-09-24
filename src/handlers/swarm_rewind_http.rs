// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Boids predator plan item 3, part 2 (#3266 / #3922, 5-agent vote `4d3ea1c5`,
//! ruling Q1): `POST /api/v1/memory_swarm_rewind`, the #1111 per-tool MCP-mirror
//! route for `memory_swarm_rewind`, on BOTH backends.
//!
//! Before this there was no agent-facing rewind on a Postgres daemon: the MCP
//! tool is stdio/SQLite-only (#1675) and the CLI refuses a Postgres store
//! (#3924), so a trait method without a route would be a PG implementation with
//! zero callers.
//!
//! # Gate (ruling Q1)
//!
//! [`crate::handlers::admin_role::require_admin`] FIRST: the server-resolved
//! admin principal (never a wire header) is the `issued_by` stamped into the
//! signed `swarm.rewind` event. This is deliberately NOT a thin wrap of
//! [`crate::mcp::handle_swarm_rewind`], whose owner gate fires only when the
//! daemon's own `AI_MEMORY_AGENT_ID` is set and whose actor falls back to the
//! daemon identity or `system` — that would attribute every tenant's rewind to
//! the daemon. No W-of-N fan-out: containment is node-local at GA (ruling R2.6).

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use super::AppState;
#[cfg(feature = "sal")]
use super::StorageBackend;
use crate::mcp::param_names;

/// `require_admin` endpoint tag (the forensic `endpoint` field).
const ENDPOINT: &str = "memory_swarm_rewind";

/// The request, parsed and clamped exactly as the MCP tool parses it.
struct RewindArgs {
    to: String,
    max_depth: usize,
    dry_run: bool,
    freeze_routines: Vec<String>,
}

fn bad_request(e: impl std::fmt::Display) -> Response {
    tracing::warn!(error = %e, "HTTP memory_swarm_rewind refusal");
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": e.to_string()})),
    )
        .into_response()
}

fn parse(body: &Value) -> Result<RewindArgs, Response> {
    let to = body[param_names::TO]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad_request("to is required"))?
        .to_string();
    // Default + clamp to the server lineage ceiling (fail-closed): a crafted
    // huge depth cannot widen the sweep past the bounded ceiling.
    let max_depth = body[param_names::MAX_DEPTH]
        .as_u64()
        .and_then(|d| usize::try_from(d).ok())
        .filter(|&d| d >= 1)
        .unwrap_or(crate::storage::LINEAGE_MAX_DEPTH)
        .min(crate::storage::LINEAGE_MAX_DEPTH);
    let dry_run = body[param_names::DRY_RUN].as_bool().unwrap_or(false);
    let freeze_routines = body[param_names::FREEZE_ROUTINES]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Ok(RewindArgs {
        to,
        max_depth,
        dry_run,
        freeze_routines,
    })
}

/// `POST /api/v1/memory_swarm_rewind`.
pub async fn handle_swarm_rewind_http(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    // The admin gate's RETURN VALUE is the issuer: an id that passed the admin
    // allowlist, the #1570 authn requirement and (under `enforce`) the #2044
    // key-attestation binding. The handler never reads `X-Agent-Id` itself.
    // `is_admin` is bound ONLY in the gate's Ok arm and threaded into the
    // admin-context constructor below (the #1062 `for_admin_checked` typed
    // dependency, the archive.rs / kg.rs majority pattern): removing or moving
    // the gate is a compile error, never a silent admin context.
    let (caller, is_admin) =
        match crate::handlers::admin_role::require_admin(&app, &headers, ENDPOINT) {
            Ok(c) => (c, true),
            Err(resp) => return resp,
        };
    let args = match parse(&body) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    // Forensic-chain entry BEFORE the write (the `release_quarantined` shape).
    // Ordering note: this precedes the backend branch, the dry-run check and
    // the record-stop gate, and that is NOT a record-plane write under stop —
    // `record_decision` appends to the forensic FILE sink, opens no database
    // connection, and records the ATTEMPT (allowed or later refused alike).
    crate::governance::audit::record_decision(
        &caller,
        "allow",
        ENDPOINT,
        "",
        crate::governance::audit::ForensicPayload::new().ident("to", &args.to),
    );

    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return rewind_via_store(&app, &caller, is_admin, &args).await;
    }
    // Only the Postgres arm builds an admin context; the sqlite funnel takes
    // the principal directly, so the proof is consumed here in that build.
    #[cfg(not(feature = "sal"))]
    let _ = is_admin;

    let lock = app.db.lock().await;
    let (root_id, kind) = match resolve_target_sqlite(&lock.0, &args.to) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if let Err(e) = crate::validate::RequestValidator::validate_id(&root_id) {
        return bad_request(e);
    }
    if !args.dry_run
        && let Err(e) = crate::storage::record_stop::gate_storage_conn(&lock.0)
    {
        return crate::handlers::errors::record_stopped_response(&e);
    }
    match crate::storage::swarm_rewind(
        &lock.0,
        &root_id,
        args.max_depth,
        &caller,
        kind,
        &args.freeze_routines,
        args.dry_run,
    ) {
        Ok(report) => Json(crate::mcp::render_swarm_rewind_report(&report)).into_response(),
        // Our own typed refusals (root not found / already contained / changed
        // under us) are safe to show; anything else is a substrate failure and
        // goes through the sanitising funnel, never rendered to the caller.
        Err(e) => match e.downcast_ref::<crate::storage::StorageError>() {
            Some(crate::storage::StorageError::InvalidArgument { reason }) => bad_request(reason),
            _ => crate::handlers::errors::handler_error_500(&e),
        },
    }
}

/// The SQLite target resolution, typed at every exit: our own refusals are
/// 400s; a database failure is a sanitised 500 (never foreign text to the
/// caller). Same semantics as the MCP resolver: a memory id in ANY lifecycle
/// state, or a checkpoint that names a root.
fn resolve_target_sqlite(
    conn: &rusqlite::Connection,
    to: &str,
) -> Result<(String, &'static str), Response> {
    let exists = |id: &str| {
        crate::storage::namespace_by_id(conn, id)
            .map(|ns| ns.is_some())
            .map_err(|e| crate::handlers::errors::handler_error_500(&e))
    };
    if exists(to)? {
        return Ok((to.to_string(), crate::mcp::REWIND_TARGET_KIND_MEMORY));
    }
    let cp = crate::checkpoints::get(conn, to)
        .map_err(|e| crate::handlers::errors::handler_error_500(&e))?;
    let Some(cp) = cp else {
        return Err(bad_request(crate::mcp::rewind_target_not_found(to)));
    };
    let root = crate::mcp::checkpoint_rewind_root(&cp)
        .ok_or_else(|| bad_request(crate::mcp::rewind_checkpoint_has_no_root(to)))?;
    if !exists(&root)? {
        return Err(bad_request(crate::mcp::rewind_checkpoint_root_not_found(
            to,
        )));
    }
    Ok((root, crate::mcp::REWIND_TARGET_KIND_CHECKPOINT))
}

/// The Postgres arm: resolve `to` (a memory id in ANY lifecycle state, so an
/// already-rewound root re-resolves idempotently, or a checkpoint that names a
/// root) through the unfiltered authz read, then `MemoryStore::swarm_rewind`.
#[cfg(feature = "sal")]
async fn rewind_via_store(
    app: &AppState,
    caller: &str,
    is_admin: bool,
    args: &RewindArgs,
) -> Response {
    // `is_admin` is threaded from the `require_admin` Ok arm (never a literal):
    // the type-level dependency `for_admin_checked` exists for.
    let ctx = crate::store::CallerContext::for_admin_checked(caller.to_string(), is_admin);
    let (root_id, kind) = match resolve_target_store(app, &ctx, &args.to).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if let Err(e) = crate::validate::RequestValidator::validate_id(&root_id) {
        return bad_request(e);
    }
    match app
        .store
        .swarm_rewind(
            &ctx,
            &root_id,
            args.max_depth,
            kind,
            &args.freeze_routines,
            args.dry_run,
        )
        .await
    {
        Ok(report) => Json(crate::mcp::render_swarm_rewind_report(&report)).into_response(),
        Err(e @ crate::store::StoreError::InvalidInput { .. }) => bad_request(e),
        Err(e) => super::store_err_to_response(e),
    }
}

#[cfg(feature = "sal")]
async fn resolve_target_store(
    app: &AppState,
    ctx: &crate::store::CallerContext,
    to: &str,
) -> Result<(String, &'static str), Response> {
    let exists = |id: String| async move { raw_exists(app, ctx, &id).await };
    if exists(to.to_string()).await? {
        return Ok((to.to_string(), crate::mcp::REWIND_TARGET_KIND_MEMORY));
    }
    let cp = app
        .store
        .checkpoint_get(ctx, to)
        .await
        .map_err(super::store_err_to_response)?;
    if let Some(cp) = cp {
        let root = crate::mcp::checkpoint_rewind_root(&cp)
            .ok_or_else(|| bad_request(crate::mcp::rewind_checkpoint_has_no_root(to)))?;
        if !exists(root.clone()).await? {
            return Err(bad_request(crate::mcp::rewind_checkpoint_root_not_found(
                to,
            )));
        }
        return Ok((root, crate::mcp::REWIND_TARGET_KIND_CHECKPOINT));
    }
    Err(bad_request(crate::mcp::rewind_target_not_found(to)))
}

/// Existence regardless of lifecycle state (the #3599 unfiltered authz read).
#[cfg(feature = "sal")]
async fn raw_exists(
    app: &AppState,
    ctx: &crate::store::CallerContext,
    id: &str,
) -> Result<bool, Response> {
    #[cfg(feature = "sal-postgres")]
    if let Some(pg) = app
        .store
        .as_any()
        .downcast_ref::<crate::store::postgres::PostgresStore>()
    {
        return pg
            .get_any(id)
            .await
            .map(|row| row.is_some())
            .map_err(super::store_err_to_response);
    }
    app.store
        .namespace_by_id(ctx, id)
        .await
        .map(|ns| ns.is_some())
        .map_err(super::store_err_to_response)
}
