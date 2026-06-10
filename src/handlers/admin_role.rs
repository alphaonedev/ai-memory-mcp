// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared admin-role gate for HTTP handlers (v0.7.0 SHIP cluster
//! #946 / #957 / #960 / #961, 2026-05-20).
//!
//! Several v0.7.0 HTTP endpoints unavoidably return corpus-scale
//! metadata that crosses tenant boundaries — operator-facing exports,
//! agent enumeration, aggregate per-namespace stats, full-quota
//! tables. Pre-cluster, those endpoints landed open by default
//! because:
//!
//! 1. The legacy `api_key_auth` middleware passes through when the
//!    operator hasn't configured an `api_key` (the default).
//! 2. No further role-check distinguished "an authenticated caller"
//!    from "an authenticated *admin* caller".
//!
//! Either gap on its own is enough to leak the deployment: an HTTP
//! caller on the default install can dump every memory across every
//! owner (`GET /api/v1/export`), enumerate every registered agent
//! (`GET /api/v1/agents`), or read corpus-scale stats
//! (`GET /api/v1/stats`).
//!
//! This module exposes the canonical role-gate helpers every admin
//! handler in the cluster shares:
//!
//! - [`is_admin_caller`] — pure predicate. Reads the
//!   `AppState.admin_agent_ids` allowlist and returns `true` iff the
//!   resolved caller matches an entry.
//! - [`require_admin`] — guard that resolves the caller from the
//!   request headers, audits the decision via the existing
//!   forensic-chain sink, and returns either the validated caller
//!   string or a sanitised `403 Forbidden` response ready to be
//!   short-circuited from the handler.
//!
//! ## Safe-by-default posture
//!
//! When `[admin].agent_ids` is unset or empty (the v0.7.0 default),
//! the allowlist is empty and every admin-class endpoint returns
//! 403 to every caller. Operators MUST opt callers in via
//! `[admin] agent_ids = [...]` in `config.toml`. This is the same
//! `pm-v3` safe-by-default posture the SAL `bypass_visibility` flag
//! uses (see `src/store/mod.rs` `CallerContext::for_admin`).
//!
//! ## Audit chain
//!
//! Every role-gate decision (allow or deny) emits a
//! `governance::audit::record_decision` entry under the
//! `admin_role` action namespace so the forensic chain captures
//! who attempted what, when, and whether they were authorised.
//! The audit fire happens BEFORE the handler observes the body so
//! the chain entry lands even if the handler errors downstream.

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use super::AppState;

/// #1570 (H6) — operator escape hatch: when truthy (`1` / `true`), the
/// admin-role gate reverts to the legacy posture where a bare
/// `X-Agent-Id` header naming an allowlisted admin id mints the admin
/// role even on a deployment with NO request authentication (no
/// `api_key` configured). Default OFF = secure: on an unauthenticated
/// deployment the self-asserted header alone can never grant admin.
/// Mirrors the #1455 `AI_MEMORY_GOVERNANCE_FAIL_OPEN_ON_ERROR`
/// fail-closed-with-explicit-opt-out convention.
pub const ENV_ADMIN_HEADER_TRUST: &str = "AI_MEMORY_ADMIN_HEADER_TRUST";

/// #1570 — `true` when the operator explicitly opted into the legacy
/// trust-the-header posture via [`ENV_ADMIN_HEADER_TRUST`].
#[must_use]
pub fn admin_header_trust_enabled() -> bool {
    std::env::var(ENV_ADMIN_HEADER_TRUST)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// #1570 — process-wide marker: `true` when the running daemon has
/// request authentication configured (an `api_key`, enforced by the
/// `api_key_auth` middleware on every non-exempt route). Set once by
/// `bootstrap_serve`; defaults to `false` so embeddings that never ran
/// the daemon bootstrap (and the unauthenticated default install) stay
/// on the secure-deny side. A request that reached an admin handler on
/// a `true` deployment has, by middleware construction, presented the
/// key — so the `X-Agent-Id` role claim is at least bound to a caller
/// holding the transport credential. (#626 request-level attested
/// identity does not exist on the HTTP read surface at v0.7.0; when it
/// lands it becomes an additional accepted authn source here.)
static REQUEST_AUTHN_CONFIGURED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// #1570 — record at boot whether request authentication (`api_key`)
/// is configured. Called by `bootstrap_serve`; test fixtures that
/// model an authenticated deployment call it with `true`.
pub fn mark_request_authn_configured(configured: bool) {
    REQUEST_AUTHN_CONFIGURED.store(configured, std::sync::atomic::Ordering::Relaxed);
}

fn request_authn_configured() -> bool {
    REQUEST_AUTHN_CONFIGURED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Pure predicate — `true` iff `caller` appears in `state`'s
/// admin-agent allowlist.
///
/// The allowlist is loaded once at daemon boot from
/// `[admin] agent_ids = [...]` in `config.toml`; entries are
/// validated against [`crate::validate::validate_agent_id`] and any
/// that fail are dropped with a `warn` log so a single typo cannot
/// lock the operator out. See [`crate::config::AdminConfig`].
///
/// Returns `false` when:
/// - the allowlist is empty (the v0.7.0 default — no admin caller
///   is configured),
/// - `caller` is an empty string,
/// - `caller` does not match any entry verbatim (no glob/prefix
///   support today — planned under #961).
#[must_use]
pub fn is_admin_caller(state: &AppState, caller: &str) -> bool {
    if caller.is_empty() {
        return false;
    }
    // v0.7.0 #980 (2026-05-20) — the `"*"` wildcard sentinel is now
    // strictly `#[cfg(test)]`-gated. Production builds NEVER admit
    // `"*"` regardless of how the allowlist got populated; even a
    // future config-loader regression that smuggles `"*"` past
    // [`crate::validate::validate_agent_id`] (which rejects it for
    // shape) cannot open every admin endpoint. The lib unit-test
    // fixture `test_app_state` at `src/handlers/tests.rs:312` seeds
    // `vec!["*"]` so legacy lib tests that issue `Body::empty()` +
    // no `X-Agent-Id` (synthetic `anonymous:req-<uuid>` principal)
    // still exercise the admin-gated happy paths after the v0.7.0
    // SHIP-cluster gates landed (#936/#940/#942/#946/#957/#960);
    // those tests run under the `cfg(test)` build and see the
    // wildcard arm below. Integration tests in `tests/*.rs` use the
    // closed allowlist (`Vec::new()`) or an explicit principal — the
    // security-gate regression coverage exercises the production
    // path. Pre-#980 the wildcard arm was always-on at runtime; an
    // `AI_MEMORY_ADMIN_AGENT_IDS=*` env var (or any
    // path that landed `"*"` in `admin_agent_ids`) admitted every
    // caller. The accompanying change in
    // `daemon_runtime::resolve_admin_agent_ids` drops the env-var
    // wildcard carve-out so the production allowlist cannot contain
    // `"*"` at all.
    #[cfg(test)]
    if state.admin_agent_ids.iter().any(|id| id == "*") {
        return true;
    }
    state.admin_agent_ids.iter().any(|id| id == caller)
}

/// Resolve the caller from `headers`, check it against the admin
/// allowlist, and either return the validated caller string OR a
/// pre-built `403 Forbidden` response the handler should
/// short-circuit on.
///
/// **Wire shape on rejection.** `403 Forbidden` with body
/// `{"error": "admin role required"}`. Intentionally generic — the
/// rejection does NOT leak whether the allowlist is empty vs. the
/// caller is just not in it, so a non-admin caller cannot probe the
/// `[admin].agent_ids` configuration. Matches the posture
/// `api_key_auth` uses on its own rejection.
///
/// **Audit.** Both the allow and the deny path emit a
/// [`crate::governance::audit::record_decision`] entry under
/// `action = "admin_role"` so the forensic chain captures every
/// attempt regardless of outcome. The audit fire happens BEFORE
/// any handler-specific work so the chain entry lands even if the
/// handler later errors. Action body carries `endpoint` so
/// operators can correlate which admin surface was probed.
///
/// # Errors
///
/// Returns `Err(Response)` when the caller fails the admin check;
/// the response is a ready-to-return 403 the handler can propagate
/// directly via `?` or `return`. Returns `Ok(caller)` when the
/// caller is admitted; the returned string is the resolved caller
/// id the handler can use for downstream calls + auditing.
pub fn require_admin(
    state: &AppState,
    headers: &HeaderMap,
    endpoint: &'static str,
) -> Result<String, Response> {
    let header_agent_id = headers
        .get(crate::HEADER_AGENT_ID)
        .and_then(|v| v.to_str().ok());
    // v0.7.0 #984 — surface `resolve_http_agent_id` errors as 400
    // BAD_REQUEST instead of papering them with the
    // `"anonymous:invalid"` sentinel. Pre-#984 a wire caller who
    // supplied an `X-Agent-Id` header that failed
    // [`crate::validate::validate_agent_id`] (invalid char class,
    // oversized, RESERVED_AGENT_IDS post-#977) reached
    // [`is_admin_caller`] with the sentinel principal. The sentinel
    // fails the admin allowlist check anyway (it's not in any
    // operator's `AdminConfig`), so the wire caller still got 403
    // — but the audit chain captured `"anonymous:invalid"` instead
    // of the actionable validation diagnostic. Worse, post-#977 a
    // wire spoof of `X-Agent-Id: daemon` would land in the audit
    // chain as `"anonymous:invalid"` rather than logging the
    // attempted spoof of a reserved name. Surfacing 400 with the
    // validator's error message gives operators the diagnostic
    // they need + closes the audit-pollution path.
    let caller = match crate::identity::resolve_http_agent_id(None, header_agent_id) {
        Ok(c) => c,
        Err(e) => {
            // Record a `deny` audit decision with the actual error
            // so the forensic chain captures the rejected probe
            // BEFORE the wire 400.
            crate::governance::audit::record_decision(
                "anonymous:resolve-failed",
                "deny",
                "admin_role",
                "",
                json!({
                    "endpoint": endpoint,
                    "outcome": "agent_id_resolve_failed",
                    "reason": e.to_string(),
                }),
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": crate::errors::msg::invalid("agent_id", e)})),
            )
                .into_response());
        }
    };

    let allowlisted = is_admin_caller(state, &caller);

    // #1570 (H6) — an allowlisted NAME is not enough by itself. The
    // `X-Agent-Id` header is self-asserted (no cryptographic binding
    // exists for it in v0.7.0), so on a deployment with NO request
    // authentication any wire caller could mint admin by typing a
    // configured id into the header. The header role-claim is honored
    // only when (a) the daemon has an `api_key` configured — the
    // middleware then guarantees every request reaching this gate
    // presented the transport credential — or (b) the operator
    // explicitly opted into the legacy posture via
    // [`ENV_ADMIN_HEADER_TRUST`]. Default = deny (fail closed, #1455
    // convention). The wire response stays the same generic 403 so a
    // probe cannot distinguish "not allowlisted" from "allowlisted but
    // unauthenticated"; the audit row carries the distinct outcome for
    // operators.
    let header_trusted = request_authn_configured() || admin_header_trust_enabled();
    let admitted = allowlisted && header_trusted;
    let outcome = if admitted {
        "admitted"
    } else if allowlisted {
        // Allowlisted name, but no authn on the deployment and the
        // trust flag is off — the #1570 secure-default refusal.
        "rejected_unauthenticated_header_identity"
    } else {
        "rejected"
    };
    crate::governance::audit::record_decision(
        &caller,
        if admitted { "allow" } else { "deny" },
        "admin_role",
        "",
        json!({
            "endpoint": endpoint,
            "outcome": outcome,
        }),
    );

    if admitted {
        Ok(caller)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response())
    }
}
