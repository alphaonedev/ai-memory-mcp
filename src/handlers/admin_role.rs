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
    let header_agent_id = headers.get("x-agent-id").and_then(|v| v.to_str().ok());
    let caller = crate::identity::resolve_http_agent_id(None, header_agent_id)
        .unwrap_or_else(|_| "anonymous:invalid".to_string());

    let admitted = is_admin_caller(state, &caller);
    crate::governance::audit::record_decision(
        &caller,
        if admitted { "allow" } else { "deny" },
        "admin_role",
        "",
        json!({
            "endpoint": endpoint,
            "outcome": if admitted { "admitted" } else { "rejected" },
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
