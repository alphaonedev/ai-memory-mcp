// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#2402] — the ADMIN HTTP twin of `ai-memory quarantine list |
//! release <id>`.
//!
//! # Why the network surface exists at all
//!
//! [#1948] documented "operator dequarantine" as the route OUT of
//! `lifecycle_state = 'quarantined'` and shipped the SAL primitive with ZERO
//! operator callers. A quarantined row is hidden from every read lane, and
//! under `asi-hard` the `AI_MEMORY_FED_QUARANTINE_UNATTRIBUTED` knob is
//! PINNED on, so on a fleet node the held row was unreachable and
//! unreleasable. The CLI twin covers an operator with shell access to the
//! host; a fleet is not operated that way at scale, so the same two verbs are
//! here.
//!
//! # The gate
//!
//! Both handlers run [`crate::handlers::admin_role::require_admin`] FIRST and
//! record the principal IT RETURNS as the audit actor. Precisely: that
//! principal is resolved from `X-Agent-Id`, and `require_admin` admits it only
//! when the name is on the operator's admin allowlist AND the deployment has
//! request authentication configured (or the explicit `#1570` legacy
//! header-trust opt-in) — and, under the `enforce` identity-binding posture,
//! only when the admin id is additionally KEY-ATTESTED to a per-agent api key
//! (`#2044`). So the recorded actor is always an ADMITTED admin principal, not
//! an arbitrary self-asserted id. The handlers themselves never read
//! `X-Agent-Id`: taking the id off the request rather than off the gate's
//! return value is exactly how the signed audit row for an operator override
//! would become attacker-chosen.
//!
//! # What is exposed
//!
//! The listing returns identifying metadata ONLY, never `content` — see
//! [`crate::models::QuarantinedMemory`]. A release routes through
//! [`crate::store::MemoryStore::operator_dequarantine`] (postgres) or
//! [`crate::db::operator_dequarantine`] (sqlite), each of which lands the
//! state change and the `memory.dequarantined` signed-chain row in ONE
//! transaction, so this surface cannot release a row without leaving a trace.
//!
//! [#2402]: https://github.com/alphaonedev/ai-memory-mcp/issues/2402
//! [#1948]: https://github.com/alphaonedev/ai-memory-mcp/issues/1948

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;

use super::AppState;
#[cfg(feature = "sal")]
use super::StorageBackend;
use crate::db;

/// `require_admin` endpoint tag for the listing.
const LIST_ENDPOINT: &str = "quarantine_list";
/// `require_admin` endpoint tag for the release.
const RELEASE_ENDPOINT: &str = "quarantine_release";

/// Query parameters for `GET /api/v1/admin/quarantine`.
#[derive(Debug, Deserialize)]
pub struct QuarantineListQuery {
    /// Restrict the listing to one namespace.
    pub namespace: Option<String>,
    /// Maximum rows to return. Clamped to
    /// [`crate::cli::quarantine::DEFAULT_LIST_LIMIT`] when absent and bounded
    /// by [`MAX_LIST_LIMIT`] regardless of what the caller asks for — an
    /// unbounded operator read of a federation-storm backlog is its own
    /// availability hazard.
    pub limit: Option<i64>,
}

/// Hard ceiling on one quarantine page. Mirrors the intent of the CLI
/// `--limit` default while refusing to let a wire caller ask for the whole
/// table in one response.
pub const MAX_LIST_LIMIT: i64 = 1_000;

/// Clamp a caller-supplied page size into `1..=MAX_LIST_LIMIT`.
///
/// A non-positive request is a caller error, not a licence to return
/// everything: it resolves to the default page rather than to `LIMIT 0`
/// (which would silently report an EMPTY quarantine — the one wrong answer
/// this endpoint must never give).
#[must_use]
pub fn clamp_limit(requested: Option<i64>) -> i64 {
    match requested {
        Some(n) if n > 0 => n.min(MAX_LIST_LIMIT),
        _ => crate::cli::quarantine::DEFAULT_LIST_LIMIT,
    }
}

/// `GET /api/v1/admin/quarantine` — list the memories currently held in
/// quarantine. Admin-gated, read-only.
pub async fn list_quarantined(
    State(app): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<QuarantineListQuery>,
) -> impl IntoResponse {
    if let Err(resp) = crate::handlers::admin_role::require_admin(&app, &headers, LIST_ENDPOINT) {
        return resp;
    }
    let limit = clamp_limit(q.limit);
    let namespace = q.namespace.as_deref();

    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        return match app.store.list_quarantined(namespace, limit).await {
            Ok(rows) => Json(json!({
                "count": rows.len(),
                (crate::models::field_names::QUARANTINED): rows,
                (crate::models::field_names::STORAGE_BACKEND): crate::storage::schema_guard::BACKEND_POSTGRES,
            }))
            .into_response(),
            Err(e) => super::store_err_to_response(e),
        };
    }

    let lock = app.db.lock().await;
    match db::list_quarantined(&lock.0, namespace, limit) {
        // Same envelope as the postgres branch, `storage_backend` included: an
        // operator adjudicating a quarantine backlog must be able to tell WHICH
        // corpus answered without inferring it from the response's shape.
        Ok(rows) => Json(json!({
            "count": rows.len(),
            (crate::models::field_names::QUARANTINED): rows,
            (crate::models::field_names::STORAGE_BACKEND): crate::storage::schema_guard::BACKEND_SQLITE,
        }))
        .into_response(),
        Err(e) => crate::handlers::errors::handler_error_500(&e),
    }
}

/// `POST /api/v1/admin/quarantine/{id}/release` — release one quarantined
/// memory back to `open`. Admin-gated; appends a `memory.dequarantined`
/// signed audit row in the same transaction as the state change.
///
/// Idempotent: an id that is not currently quarantined answers `200` with
/// `released: false` and writes NOTHING (no state change, no audit row). It is
/// deliberately not a `404`: "unknown id" and "already released" are
/// indistinguishable to a caller who cannot see quarantined rows, and turning
/// the difference into a status code would leak the existence of rows this
/// endpoint is not returning.
pub async fn release_quarantined(
    State(app): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // The admin gate's RETURN VALUE is the audit actor: an id that passed the
    // admin allowlist, the #1570 authn requirement, and (under `enforce`) the
    // #2044 key-attestation binding. The handler never reads `X-Agent-Id`
    // itself — that is what keeps the signed row for an operator override from
    // being attacker-chosen.
    let caller = match crate::handlers::admin_role::require_admin(&app, &headers, RELEASE_ENDPOINT)
    {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // Forensic-chain entry BEFORE the write, matching `run_gc` / `import` /
    // `export`: the operator who triggered an override is captured even if
    // the storage write then fails.
    crate::governance::audit::record_decision(
        &caller,
        "allow",
        RELEASE_ENDPOINT,
        "",
        json!({ "id": id }),
    );

    #[cfg(feature = "sal")]
    if matches!(app.storage_backend, StorageBackend::Postgres) {
        // `for_admin_checked` — the #1062 handler-side constructor — rather
        // than a hand-built struct: it makes the dependency on the admin gate
        // visible in the TYPE SIGNATURE instead of leaving a bare
        // `bypass_visibility: true` for a reviewer to correlate with a
        // `require_admin` call twenty lines up. The `true` is sound because
        // `require_admin` returned `Ok` above; there is no other way to reach
        // this line. Quarantined rows are hidden from tenant visibility, so
        // the release lane must bypass the scope filter to see the row at all.
        let ctx = crate::store::CallerContext::for_admin_checked(caller.clone(), true);
        return match app.store.operator_dequarantine(&ctx, &id).await {
            Ok(released) => Json(release_body(&id, released)).into_response(),
            Err(e) => super::store_err_to_response(e),
        };
    }

    let mut lock = app.db.lock().await;
    match db::operator_dequarantine(&mut lock.0, &id, &caller) {
        Ok(released) => Json(release_body(&id, released)).into_response(),
        Err(e) => crate::handlers::errors::handler_error_500(&e),
    }
}

/// Shared release response body, so both backends answer byte-identically.
fn release_body(id: &str, released: bool) -> serde_json::Value {
    json!({
        "id": id,
        "released": released,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_or_nonsense_limit_falls_back_to_the_default_page_not_to_zero() {
        assert_eq!(
            clamp_limit(None),
            crate::cli::quarantine::DEFAULT_LIST_LIMIT
        );
        assert_eq!(
            clamp_limit(Some(0)),
            crate::cli::quarantine::DEFAULT_LIST_LIMIT
        );
        assert_eq!(
            clamp_limit(Some(-5)),
            crate::cli::quarantine::DEFAULT_LIST_LIMIT,
            "LIMIT 0 would report an EMPTY quarantine — the one wrong answer here"
        );
    }

    #[test]
    fn a_caller_cannot_ask_for_an_unbounded_page() {
        assert_eq!(clamp_limit(Some(10)), 10);
        assert_eq!(clamp_limit(Some(MAX_LIST_LIMIT)), MAX_LIST_LIMIT);
        assert_eq!(clamp_limit(Some(i64::MAX)), MAX_LIST_LIMIT);
    }

    #[test]
    fn the_release_body_is_backend_blind() {
        assert_eq!(release_body("m1", true)["released"], json!(true));
        assert_eq!(release_body("m1", false)["released"], json!(false));
        assert_eq!(release_body("m1", true)["id"], json!("m1"));
    }
}
