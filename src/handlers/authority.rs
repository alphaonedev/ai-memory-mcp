// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3549 — the HTTP caller-authority chokepoint.
//!
//! One `axum` middleware, composed in `crate::build_router_with_timeout`
//! IMMEDIATELY INSIDE [`crate::handlers::api_key_auth`] (so it observes the
//! header that middleware bound to an enrolled per-agent key), that resolves
//! [`crate::identity::authority::Authority`] ONCE per request and attaches
//! it to the request extensions. Every `.route(...)` registration sits
//! beneath this layer; the structural guard
//! `tests/authority_boundary_structural_3549.rs` enumerates them and proves
//! it, and the few paths the layer deliberately does NOT gate are the
//! checked-in allowlist with reasons ([`AUTHORITY_EXEMPT_EXACT`] /
//! [`AUTHORITY_EXEMPT_PREFIXES`]).
//!
//! # Fail-closed
//!
//! A PRESENT but malformed / reserved `X-Agent-Id` is refused here with the
//! same typed `400` the handlers have returned since #984, so a malformed
//! principal assertion never reaches a handler on ANY route — including the
//! ones that previously ignored the header. A request with NO asserted
//! identity is NOT refused: it is the documented anonymous per-request
//! principal, which owns nothing and sees only non-private rows.
//!
//! # What this layer does NOT do
//!
//! It makes no object decision (ruling 1 of the #3581 vote): which row,
//! which namespace, which owner is the handler's predicate
//! ([`crate::visibility::is_readable_on_query`], the IDOR gates, the admin
//! gate). It does not touch the federation boundary: `/api/v1/sync/*` is
//! authenticated by `receive_auth` / `signing_check` against the peer key,
//! not by `X-Agent-Id` (ruling 4).

use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::identity::authority::{Authority, HttpAuthorityInputs};

/// Exact paths the resolver does not gate: the liveness / scrape probes.
/// A probe carries no identity and MUST NOT fail on one — an orchestrator
/// that loses liveness on a header quirk kills a healthy node.
pub const AUTHORITY_EXEMPT_EXACT: &[&str] = &[
    super::routes::HEALTH,
    super::routes::MONITORING_STATUS,
    super::routes::MONITORING_METRICS,
    super::routes::METRICS_BARE,
    super::routes::METRICS,
];

/// The federation receive path prefix (`/api/v1/sync/push`, `/sync/since`).
/// ONE definition, shared with the `api_key_auth` mTLS bypass.
pub const SYNC_PREFIX: &str = "/api/v1/sync/";

/// Path prefixes the resolver does not gate: the federation receive
/// boundary, which authenticates the PEER (`X-Peer-Id` + Ed25519 signature +
/// nonce + enrollment) and is its own boundary with its own guard.
pub const AUTHORITY_EXEMPT_PREFIXES: &[&str] = &[SYNC_PREFIX];

/// `true` when `path` is outside the resolver's scope. Pure, so the
/// structural guard and the layer share one definition.
#[must_use]
pub fn is_authority_exempt(path: &str) -> bool {
    AUTHORITY_EXEMPT_EXACT.contains(&path)
        || AUTHORITY_EXEMPT_PREFIXES
            .iter()
            .any(|p| path.starts_with(p))
}

/// The server-held state the layer resolves against. Header trust (the
/// #1570 "request authentication is configured" fact) is read from the
/// boot-seeded `admin_role::request_authn_configured` flag, the same source
/// `require_admin` consults, so the two can never disagree.
#[derive(Clone)]
pub struct AuthorityLayerState {
    /// The daemon state (admin allowlist, enrolled per-agent keys, posture).
    pub app: super::AppState,
}

/// The stable audit `kind` for a refusal recorded by this layer.
pub const AUDIT_KIND_AUTHORITY: &str = "authority";

/// The middleware. See the module docs.
pub async fn authority_layer(
    State(state): State<AuthorityLayerState>,
    mut req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    if is_authority_exempt(&path) {
        return next.run(req).await;
    }

    let header_agent_id = req
        .headers()
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // The per-agent-key principal, if the presented key is enrolled. ONE
    // snapshot (#3418) so the emptiness fact and the lookup agree.
    let enrolled = state.app.enrolled_agent_keys.snapshot();
    let key_bound_principal: Option<String> = req
        .headers()
        .get(crate::HEADER_API_KEY)
        .and_then(|v| v.to_str().ok())
        .and_then(|token| {
            enrolled
                .get(&super::identity_binding::api_key_sha256_hex(token))
                .cloned()
        });

    let header_trusted = super::admin_role::request_authn_configured()
        || super::admin_role::admin_header_trust_enabled();

    let resolved = Authority::resolve_http(HttpAuthorityInputs {
        header_agent_id: header_agent_id.as_deref(),
        key_bound_principal: key_bound_principal.as_deref(),
        identity_mode: state.app.http_identity_mode,
        enrolled_keys_present: !enrolled.is_empty(),
        admin_allowlist: &state.app.admin_agent_ids,
        header_trusted,
    });

    match resolved {
        Ok(authority) => {
            req.extensions_mut().insert(authority);
            next.run(req).await
        }
        Err(e) => {
            // Forensic capture BEFORE the wire 400 — the chain records the
            // rejected probe exactly as `require_admin` did when it was the
            // first gate a malformed header met (#984).
            crate::governance::audit::record_decision(
                "anonymous:resolve-failed",
                "deny",
                AUDIT_KIND_AUTHORITY,
                "",
                json!({
                    "endpoint": path,
                    "outcome": "agent_id_resolve_failed",
                    "reason": e.to_string(),
                }),
            );
            tracing::warn!(
                target: super::AUTHZ_TRACE_TARGET,
                endpoint = %path,
                error = %e,
                "#3549: request refused at the authority chokepoint"
            );
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "code": crate::errors::error_codes::VALIDATION_FAILED,
                    "error": e.to_string(),
                })),
            )
                .into_response()
        }
    }
}

/// Read the resolved authority back out of a handler's request parts.
/// `None` only on an exempt path or a router built without the layer
/// (test scaffolds) — production routes always carry one.
#[must_use]
pub fn resolved_authority(extensions: &axum::http::Extensions) -> Option<&Authority> {
    extensions.get::<Authority>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exempt_set_is_exactly_probes_and_federation_3549() {
        assert!(is_authority_exempt(crate::handlers::routes::HEALTH));
        assert!(is_authority_exempt(crate::handlers::routes::METRICS));
        assert!(is_authority_exempt(crate::handlers::routes::METRICS_BARE));
        assert!(is_authority_exempt(crate::handlers::routes::SYNC_PUSH));
        assert!(is_authority_exempt(crate::handlers::routes::SYNC_SINCE));
        assert!(!is_authority_exempt(crate::handlers::routes::MEMORIES));
        assert!(!is_authority_exempt(crate::handlers::routes::STATS));
        assert!(!is_authority_exempt("/api/v1/memories/abc"));
    }
}
