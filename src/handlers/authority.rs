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
//! # The identity funnel (#9341)
//!
//! Under [`HttpIdentityMode::Enforce`] (per-agent keys enrolled or not, the
//! shared key configured or not; 3-agent vote (71472661) B-1), a request
//! that NAMES a principal (`X-Agent-Id` present) without
//! proving it is refused here, once, with `403 attested_identity_required`
//! ([`refuse_unproven_named_principal`]). Proven means an enrolled per-agent
//! key bound to that agent or a mapped mTLS certificate (#8590): the
//! [`Binding::is_key_bound`] rungs. The shared API key is a transport
//! credential and proves no principal. The per-handler gates stay as defence
//! in depth. The exempt paths above never reach it. Under Advisory the same
//! request is served and REPORTED (deduplicated WARN plus a counter, nothing
//! persisted: [`super::advisory_identity_report`]).
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

use crate::config::HttpIdentityMode;
use crate::identity::authority::{Authority, Binding, HttpAuthorityInputs};

/// The stable wire `error` of a funnel refusal: the SAME code the
/// per-handler gate [`super::identity_binding::enforce_sensitive_identity`]
/// returns, so a client sees one contract whichever gate fires first.
pub const ATTESTED_IDENTITY_REQUIRED: &str = "attested_identity_required";

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

    // #9342 — a PRESENT header that is not visible ASCII is refused, never
    // read as "no header" (which would mint the anonymous principal).
    let header_agent_id = match req.headers().get(crate::HEADER_AGENT_ID) {
        None => None,
        Some(v) => match v.to_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => return unreadable_header_refusal(&path),
        },
    };

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

    // #8357 — the agent the presenting mTLS client certificate is bound to.
    // `api_key_auth` (the outer layer) already refused or rewrote a
    // differing `X-Agent-Id`, so a match here proves the principal.
    let cert_bound: Option<String> = req
        .extensions()
        .get::<crate::mtls_agent_binding::ClientCertAgentBinding>()
        .and_then(|b| b.effective_agent_id().map(str::to_string));

    let resolved = Authority::resolve_http_with_cert(
        HttpAuthorityInputs {
            header_agent_id: header_agent_id.as_deref(),
            key_bound_principal: key_bound_principal.as_deref(),
            identity_mode: state.app.http_identity_mode,
            enrolled_keys_present: !enrolled.is_empty(),
            admin_allowlist: &state.app.admin_agent_ids,
            header_trusted,
        },
        cert_bound.as_deref(),
    );

    match resolved {
        Ok(authority) => {
            if let Some(refusal) = refuse_unproven_named_principal(
                state.app.http_identity_mode,
                header_agent_id.as_deref(),
                &authority,
                &path,
            ) {
                return refusal;
            }
            super::advisory_identity_report::report_unproven_named_principal(
                state.app.http_identity_mode,
                req.headers()
                    .get(crate::HEADER_API_KEY)
                    .and_then(|v| v.to_str().ok()),
                header_agent_id.as_deref(),
                &authority,
                &path,
            );
            let cert_proven = (authority.binding() == Binding::ClientCert)
                .then(|| authority.principal().to_string());
            req.extensions_mut().insert(authority);
            match cert_proven {
                // #8590 — the handler-side gate re-derives the caller's level
                // from the request; scope the cert proof so it counts there.
                Some(principal) => {
                    super::identity_binding::with_cert_proven_principal(principal, next.run(req))
                        .await
                }
                None => next.run(req).await,
            }
        }
        Err(e) => {
            // Forensic capture BEFORE the wire 400 — the chain records the
            // rejected probe exactly as `require_admin` did when it was the
            // first gate a malformed header met (#984).
            crate::governance::audit::record_decision(
                crate::identity::sentinels::ANONYMOUS_RESOLVE_FAILED,
                "deny",
                AUDIT_KIND_AUTHORITY,
                "",
                crate::governance::audit::ForensicPayload::new()
                    .ident("endpoint", &path)
                    .label("outcome", "agent_id_resolve_failed")
                    // The error text can echo the hostile header value.
                    .commit("reason", &e.to_string()),
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

/// #9341 — THE identity funnel. `Some(403)` when the request names a
/// principal it has not proven, under Enforce (keys enrolled or not); `None`
/// otherwise. A header naming an anonymous sentinel is a client assertion,
/// not the server-minted anonymous principal, so it is refused too. An absent
/// or empty header is the anonymous principal and passes (it owns nothing).
#[must_use]
pub fn refuse_unproven_named_principal(
    mode: HttpIdentityMode,
    header_agent_id: Option<&str>,
    authority: &Authority,
    endpoint: &str,
) -> Option<Response> {
    // 3-agent vote (71472661) B-1: Enforce refuses in all four states (keys
    // enrolled or not, shared key configured or not); only a per-agent key
    // or a mapped certificate proves a name.
    if mode != HttpIdentityMode::Enforce {
        return None;
    }
    let named = header_agent_id.is_some_and(|h| !h.is_empty());
    if !named || authority.binding().is_key_bound() {
        return None;
    }
    Some(attested_identity_refusal(
        authority.principal(),
        authority.binding().as_str(),
        endpoint,
    ))
}

/// #9341 — the one `403 attested_identity_required` the funnel answers, with
/// its forensic record and WARN. [`refuse_unproven_named_principal`] (header)
/// and [`bind_request_named_principal`] (body / query) share it so a refusal
/// is byte for byte the same whichever field named the principal.
fn attested_identity_refusal(actor: &str, binding: &'static str, endpoint: &str) -> Response {
    crate::governance::audit::record_decision(
        actor,
        "deny",
        AUDIT_KIND_AUTHORITY,
        "",
        crate::governance::audit::ForensicPayload::new()
            .ident("endpoint", endpoint)
            .label("outcome", ATTESTED_IDENTITY_REQUIRED)
            .label("binding", binding),
    );
    tracing::warn!(
        target: super::AUTHZ_TRACE_TARGET,
        endpoint,
        binding,
        "#9341 enforce: refused an unproven named principal at the authority chokepoint"
    );
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": ATTESTED_IDENTITY_REQUIRED,
            "message": "X-Agent-Id is self-asserted; present the agent's enrolled \
                        per-agent api-key (X-API-Key) or a mapped client \
                        certificate to act as this principal",
            "endpoint": endpoint,
        })),
    )
        .into_response()
}

/// What [`bind_request_named_principal`] decided for a principal a request
/// names in its BODY or QUERY (PR 9390 H1).
#[derive(Debug)]
pub enum RequestPrincipal {
    /// Enforce: act as exactly this principal, the funnel's
    /// `authority.principal()` (proven, or server-minted anonymous).
    Funnel(String),
    /// Off / Advisory: the handler keeps its pre-#9341 resolution unchanged.
    Unchanged,
    /// Enforce: the named principal is not the proven one; answer this, the
    /// funnel's exact refusal, before any read or write.
    Refused(Response),
}

/// PR 9390 H1 — THE one way a handler turns a principal named in a request
/// BODY or QUERY field into the principal it acts as.
///
/// Under [`HttpIdentityMode::Enforce`] (any key count, zero included): an
/// absent or empty claim yields the funnel principal; a claim EQUAL to a
/// PROVEN principal ([`Binding::is_key_bound`]) yields it; anything else (the
/// anonymous shared-key caller naming an id, a proven caller naming a
/// different id, no resolved authority at all) is refused with the funnel's
/// `403`. A body name is the same claim as a header name, so it gets the same
/// answer. Under Advisory the claim is reported exactly as a header claim is
/// (V-4) and the handler is left unchanged; under Off nothing happens.
#[must_use]
pub fn bind_request_named_principal(
    mode: HttpIdentityMode,
    authority: Option<&Authority>,
    presented_key: Option<&str>,
    claimed: Option<&str>,
    endpoint: &str,
) -> RequestPrincipal {
    let claimed = claimed.filter(|c| !c.is_empty());
    match mode {
        HttpIdentityMode::Off => RequestPrincipal::Unchanged,
        HttpIdentityMode::Advisory => {
            if let Some(authority) = authority {
                super::advisory_identity_report::report_unproven_named_principal(
                    mode,
                    presented_key,
                    claimed,
                    authority,
                    endpoint,
                );
            }
            RequestPrincipal::Unchanged
        }
        HttpIdentityMode::Enforce => match (authority, claimed) {
            (Some(a), None) => RequestPrincipal::Funnel(a.principal().to_string()),
            (Some(a), Some(c)) if a.binding().is_key_bound() && c == a.principal() => {
                RequestPrincipal::Funnel(a.principal().to_string())
            }
            (Some(a), Some(_)) => RequestPrincipal::Refused(attested_identity_refusal(
                a.principal(),
                a.binding().as_str(),
                endpoint,
            )),
            // A router without the authority layer (test scaffolds only):
            // nothing is proven, so a named claim is refused, fail closed.
            (None, Some(_)) => RequestPrincipal::Refused(attested_identity_refusal(
                crate::identity::sentinels::ANONYMOUS_RESOLVE_FAILED,
                "none",
                endpoint,
            )),
            (None, None) => RequestPrincipal::Unchanged,
        },
    }
}

/// #9342 — the typed `400` for a present `X-Agent-Id` that is not visible
/// ASCII. The raw bytes are never echoed.
fn unreadable_header_refusal(path: &str) -> Response {
    crate::governance::audit::record_decision(
        crate::identity::sentinels::ANONYMOUS_RESOLVE_FAILED,
        "deny",
        AUDIT_KIND_AUTHORITY,
        "",
        crate::governance::audit::ForensicPayload::new()
            .ident("endpoint", path)
            .label("outcome", "agent_id_unreadable"),
    );
    tracing::warn!(
        target: super::AUTHZ_TRACE_TARGET,
        endpoint = %path,
        "#9342: refused a non-ASCII X-Agent-Id at the authority chokepoint"
    );
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "code": crate::errors::error_codes::VALIDATION_FAILED,
            "error": "X-Agent-Id must be visible ASCII",
        })),
    )
        .into_response()
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

    /// The `authority` rows of the sink in `dir` whose `endpoint` is `ep`.
    fn authority_rows_9390(
        dir: &std::path::Path,
        ep: &str,
    ) -> Vec<crate::governance::audit::ForensicDecision> {
        let mut rows = Vec::new();
        for entry in std::fs::read_dir(dir).expect("sink dir").flatten() {
            let body = std::fs::read_to_string(entry.path()).unwrap_or_default();
            for line in body.lines().filter(|l| !l.trim().is_empty()) {
                if let Ok(row) =
                    serde_json::from_str::<crate::governance::audit::ForensicDecision>(line)
                    && row.kind == AUDIT_KIND_AUTHORITY
                    && row.payload.get("endpoint").and_then(|v| v.as_str()) == Some(ep)
                {
                    rows.push(row);
                }
            }
        }
        rows
    }

    fn inputs_9390<'a>(
        header: Option<&'a str>,
        key_bound: Option<&'a str>,
        admins: &'a [String],
    ) -> HttpAuthorityInputs<'a> {
        HttpAuthorityInputs {
            header_agent_id: header,
            key_bound_principal: key_bound,
            identity_mode: HttpIdentityMode::Enforce,
            enrolled_keys_present: false,
            admin_allowlist: admins,
            header_trusted: true,
        }
    }

    /// PR 9390 L1 — a funnel refusal never names the claimed, unproven agent
    /// as the actor: the actor is the server-minted anonymous principal (or
    /// the key-bound principal when one is proven), and the claim is the
    /// separate `claimed_agent_id`, escaped (newline, control byte) and cut.
    #[test]
    fn refusal_audit_actor_is_never_the_claimed_id_9390() {
        use crate::governance::audit;
        let _sink = audit::forensic_sink_test_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().expect("sink dir");
        audit::shutdown();
        audit::init(tmp.path(), None).expect("sink init");
        let run = uuid::Uuid::new_v4().simple().to_string();
        let ep = |case: &str| format!("/api/v1/audit-9390-{case}-{run}");
        let admins: Vec<String> = Vec::new();

        // (a) header path: a shared-key caller names bob.
        let header_bob =
            Authority::resolve_http(inputs_9390(Some("bob"), None, &admins)).expect("resolve");
        assert!(
            refuse_unproven_named_principal(
                HttpIdentityMode::Enforce,
                Some("bob"),
                &header_bob,
                &ep("header"),
            )
            .is_some()
        );
        // (b) body path: the anonymous caller names "bob\n<BEL>x" in a body.
        let anon = Authority::resolve_http(inputs_9390(None, None, &admins)).expect("resolve");
        let hostile = "bob\n\u{7}x";
        assert!(matches!(
            bind_request_named_principal(
                HttpIdentityMode::Enforce,
                Some(&anon),
                None,
                Some(hostile),
                &ep("body"),
            ),
            RequestPrincipal::Refused(_)
        ));
        // (c) proven alice names bob in a body.
        let alice = Authority::resolve_http(inputs_9390(Some("alice"), Some("alice"), &admins))
            .expect("resolve");
        assert!(matches!(
            bind_request_named_principal(
                HttpIdentityMode::Enforce,
                Some(&alice),
                None,
                Some("bob"),
                &ep("proven"),
            ),
            RequestPrincipal::Refused(_)
        ));
        // (d) no authority at all (scaffold router) names bob.
        assert!(matches!(
            bind_request_named_principal(
                HttpIdentityMode::Enforce,
                None,
                None,
                Some("bob"),
                &ep("none"),
            ),
            RequestPrincipal::Refused(_)
        ));
        // (e) a 100K claim: cut, bounded, linear.
        let long = "z".repeat(100_000);
        let started = std::time::Instant::now();
        assert!(matches!(
            bind_request_named_principal(
                HttpIdentityMode::Enforce,
                Some(&anon),
                None,
                Some(&long),
                &ep("long"),
            ),
            RequestPrincipal::Refused(_)
        ));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "a 100K claim is refused in bounded time: {:?}",
            started.elapsed()
        );
        audit::shutdown();

        let one = |case: &str| {
            let rows = authority_rows_9390(tmp.path(), &ep(case));
            assert_eq!(rows.len(), 1, "{case}: exactly one refusal row: {rows:?}");
            let row = rows.into_iter().next().expect("one row");
            let claimed = row
                .payload
                .get("claimed_agent_id")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            (row.actor, claimed)
        };
        let (actor, claimed) = one("header");
        assert!(
            crate::identity::is_anonymous_request_id(&actor) && actor != "bob",
            "header refusal actor is server-minted, not the claim: {actor}"
        );
        assert_eq!(claimed, serde_json::json!("bob"));
        let (actor, claimed) = one("body");
        assert_eq!(actor, anon.principal(), "body refusal actor");
        assert_eq!(claimed, serde_json::json!("bob\\n\\u{7}x"));
        let (actor, claimed) = one("proven");
        assert_eq!(actor, "alice", "a proven caller stays the actor");
        assert_eq!(claimed, serde_json::json!("bob"));
        let (actor, claimed) = one("none");
        assert_eq!(actor, crate::identity::sentinels::ANONYMOUS_RESOLVE_FAILED);
        assert_eq!(claimed, serde_json::json!("bob"));
        let (actor, claimed) = one("long");
        assert_eq!(actor, anon.principal());
        let shown = claimed.as_str().unwrap_or_default().to_string();
        assert!(
            shown.len() <= 256 && shown.ends_with("...(cut)") && shown.starts_with("zzz"),
            "a long claim is cut to the ident length: {} bytes",
            shown.len()
        );
    }
}
