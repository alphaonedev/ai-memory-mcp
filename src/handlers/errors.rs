// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! HTTP error-sanitization helpers — issue #851 (Wave-2 Tier-A3 SECURITY).
//!
//! HTTP handler responses were echoing raw db/serde/federation error strings
//! to unauthenticated callers, exposing SQL fragments, constraint names,
//! peer URLs, agent_ids, and user-supplied ids paired with internal error
//! detail. The 3 helpers below replace the prior inline patterns at every
//! leak site (15 fixed, 3 deferred to operator review per the audit
//! finding doc).
//!
//! `sanitize_bulk_row_error` is invoked at per-row bulk-endpoint failure
//! sites (POST /import, POST /memories/bulk) where each row's error
//! previously surfaced verbatim in an `errors[]` array. It maps the raw
//! string to one of five allowlisted classification labels (validation /
//! conflict / not found / forbidden / replication unavailable) so the
//! caller still learns the failure CATEGORY (validation vs conflict vs
//! internal) without echoing the raw inner detail. The full detail is
//! always logged via `tracing::warn!` so operators can debug.
//!
//! `internal_error_response` is the analogue for top-level 5xx responses:
//! it logs the raw error at `error` level and returns the canonical
//! "internal server error" JSON body. Used at sites where the prior code
//! pushed an `e.to_string()` straight into the response body.
//!
//! `bad_request_opaque` is the 400 analogue for sites that previously
//! forwarded an `mcp::handle_*` `Result<_, String>` error verbatim, where
//! the inner string includes raw rusqlite text from
//! `db::insert(...).map_err(|e| e.to_string())` calls inside the MCP
//! handler.
//!
//! Wire compatibility is preserved: response shape stays
//! `{"error": "<message>"}` and HTTP status codes are unchanged. Only the
//! CONTENT of the message is hardened.

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

/// Sanitize a per-row error message that originated in a bulk endpoint
/// (`bulk_create`, `import_memories`, federation fanout). Returns a short
/// classification string safe to echo to an unauthenticated caller.
///
/// The classifier matches on stable substrings produced by `validate::*`,
/// `db::*`, and `crate::federation::*`. Anything that doesn't match falls
/// back to `"internal error"`, which is the safe default.
///
/// Public (rather than `pub(crate)`) so the issue #851 regression test
/// crate (`tests/handler_error_sanitization.rs`) can pin the
/// classifier's allowlist directly without going through the router.
#[must_use]
pub fn sanitize_bulk_row_error(raw: &str) -> &'static str {
    classify_bulk_row_error(raw).label
}

/// #2552 / #2588 — the typed classification of a per-row bulk failure.
///
/// `label` is the #851 sanitized, allowlisted string echoed to the caller;
/// `code` is the machine-readable [`crate::errors::error_codes`] slug a fleet
/// loader switches on to decide retry-vs-backoff-vs-quarantine; `retryable`
/// drives the whole-request status precedence when NOTHING was persisted (a
/// retryable cause must win over a permanent one, so a batch that was half
/// quota-rejected and half invalid reports the retryable 429 rather than
/// telling the fleet "never retry" and permanently dropping the writable
/// rows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BulkRowErrorClass {
    /// Machine-readable slug from [`crate::errors::error_codes`].
    pub code: &'static str,
    /// #851 sanitized human label — the historical `errors[]` string.
    pub label: &'static str,
    /// HTTP status this cause maps to on the single-row surface.
    pub status: StatusCode,
    /// Whether re-submitting the same row could succeed later.
    pub retryable: bool,
}

/// #2552 / #2588 — classify a raw per-row bulk failure into its typed class.
///
/// The classifier matches on stable substrings produced by `validate::*`,
/// `crate::quotas::*`, `db::*`, and `crate::federation::*`. Anything that
/// doesn't match falls back to the safe `"internal error"` default.
///
/// **#2588 — the quota arm is FIRST and load-bearing.** Pre-#2588 there was no
/// quota arm at all, so `"QUOTA_EXCEEDED: agent qtest namespace q hit
/// memories_per_day (current=5, max=5)"` matched nothing and fell through to
/// `"internal error"`. A corpus load that lost 31,000 rows to the per-agent
/// write quota was reported as `200 {"created":0,"errors":["internal error",
/// …]}` with no server-side log line — a silent, unintentional loss of durable
/// writes and the single most severe defect in this cluster. Classifying it
/// costs no confidentiality: the IDENTICAL text is already returned verbatim
/// to the same caller by the single-row `429 QUOTA_EXCEEDED` envelope
/// (`handlers::create`). The match is on the `quota_exceeded` slug rather than
/// a bare `"quota"` so the SUBSTRATE-failure message
/// (`crate::errors::msg::QUOTA_CHECK_FAILED` = `"quota check failed"`) keeps
/// classifying as an internal error — a failed quota READ is not a quota
/// BREACH, and telling a loader to back off when the substrate is broken would
/// be the wrong instruction.
#[must_use]
pub fn classify_bulk_row_error(raw: &str) -> BulkRowErrorClass {
    let lower = raw.to_ascii_lowercase();
    // #2588 — quota FIRST: retryable, typed, and already caller-visible on
    // the single-row surface.
    if lower.contains("quota_exceeded") {
        return BulkRowErrorClass {
            code: crate::errors::error_codes::QUOTA_EXCEEDED,
            label: "quota exceeded",
            status: StatusCode::TOO_MANY_REQUESTS,
            retryable: true,
        };
    }
    // Validation errors are template strings the caller's input can
    // synthesise on the client side; they don't carry DB/path/peer
    // state. Keep them informative.
    if lower.contains("cannot be empty")
        || lower.contains("exceeds max")
        || lower.contains("invalid characters")
        || lower.contains("invalid control characters")
        || lower.contains("must be")
        || lower.contains("required")
    {
        return BulkRowErrorClass {
            code: crate::errors::error_codes::VALIDATION_FAILED,
            label: "validation failed",
            status: StatusCode::BAD_REQUEST,
            retryable: false,
        };
    }
    if lower.contains("already exists in namespace") || lower.contains("unique constraint") {
        return BulkRowErrorClass {
            code: crate::errors::error_codes::CONFLICT,
            label: "conflict: already exists",
            status: StatusCode::CONFLICT,
            retryable: false,
        };
    }
    if lower.contains("not found") {
        return BulkRowErrorClass {
            code: crate::errors::error_codes::NOT_FOUND,
            label: "not found",
            status: StatusCode::NOT_FOUND,
            retryable: false,
        };
    }
    if lower.contains("denied by governance") || lower.contains("permission") {
        return BulkRowErrorClass {
            code: crate::errors::error_codes::GOVERNANCE_REFUSED,
            label: "forbidden",
            status: StatusCode::FORBIDDEN,
            retryable: false,
        };
    }
    if lower.contains("quorum") || lower.contains("fanout") || lower.contains("peer") {
        return BulkRowErrorClass {
            code: crate::errors::error_codes::REPLICATION_UNAVAILABLE,
            label: "replication unavailable",
            status: StatusCode::SERVICE_UNAVAILABLE,
            retryable: true,
        };
    }
    BulkRowErrorClass {
        code: crate::errors::error_codes::INTERNAL_ERROR,
        label: "internal error",
        status: StatusCode::INTERNAL_SERVER_ERROR,
        retryable: true,
    }
}

/// Standard 500 response used at sites where the prior code leaked the
/// raw error into the body. Logs the underlying `err` at `error` level
/// (with the optional `context` tag) and returns a constant JSON body.
///
/// Currently used by the regression test scaffolding and reserved for
/// future remediation patches that need to swap a bespoke 500 site to
/// the canonical sanitized path; production call sites already use the
/// inline log-then-respond pattern that predated this helper.
#[allow(dead_code)]
pub(crate) fn internal_error_response(
    context: &'static str,
    err: &dyn std::fmt::Display,
) -> axum::response::Response {
    tracing::error!("{context}: {err}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": crate::errors::msg::INTERNAL_SERVER_ERROR})),
    )
        .into_response()
}

/// #1558 batch 5 wave 2 — the canonical "handler error" 500 path.
///
/// Replaces the 37 inline `tracing::error!("handler error: {e}")` +
/// sanitized-body 500 sites across the handler modules with one
/// definition. Log line and response body are BYTE-IDENTICAL to the
/// prior inline pattern; only the spelling is centralised.
pub(crate) fn handler_error_500(e: &dyn std::fmt::Display) -> axum::response::Response {
    tracing::error!("handler error: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": crate::errors::msg::INTERNAL_SERVER_ERROR})),
    )
        .into_response()
}

/// #1558 batch 5 wave 2 — the canonical governance-consultation 500
/// path: logs `"governance error: {e}"` and returns the sanitized
/// `"governance check failed"` envelope. Byte-identical to the prior
/// inline pattern at the create / update / bulk-update sites.
pub(crate) fn governance_error_500(e: &dyn std::fmt::Display) -> axum::response::Response {
    tracing::error!("governance error: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": crate::errors::msg::GOVERNANCE_CHECK_FAILED})),
    )
        .into_response()
}

/// Standard 400 response for an opaque caller-side failure (mirror of
/// [`internal_error_response`] for sites that previously echoed an
/// arbitrary `String` error from an MCP handler back to the wire). The
/// raw error is logged at `warn` level (the request is the caller's
/// fault, not the server's) and a constant safe message is returned.
pub(crate) fn bad_request_opaque(
    context: &'static str,
    err: &dyn std::fmt::Display,
) -> axum::response::Response {
    tracing::warn!("{context}: {err}");
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "invalid request"})),
    )
        .into_response()
}

/// #869 (2026-05-18) — serialise a value to `serde_json::Value` and,
/// on failure, return a 500 envelope instead of the silent
/// `unwrap_or_default()` that would have masked the error as
/// `Value::Null` (or worse, an empty `{}` body paired with a 201
/// Created envelope).
///
/// Returns:
/// - `Ok(value)` — the serialised JSON value; the caller wraps it in
///   the success status code of its choice.
/// - `Err(response)` — a 500 response the caller MUST return verbatim;
///   the error has already been logged at `error` level with the
///   `context` tag so operators can diagnose the encode failure.
///
/// `Memory` and most response structs derive `Serialize` over owned
/// `String`/`Vec`/`HashMap` fields and only fail on the adversarial
/// inputs that produce non-string map keys, NaN/Inf floats, or
/// recursion past `serde_json`'s recursion limit. For typed structs
/// the failure is therefore vanishingly rare in production — but the
/// silent `unwrap_or_default` returning `201 Created {}` was a true
/// correctness bug (#869), so a typed 500 envelope is the right
/// surface for the rare failure case.
pub(crate) fn to_value_or_500<T: serde::Serialize + ?Sized>(
    context: &'static str,
    value: &T,
) -> Result<serde_json::Value, axum::response::Response> {
    serde_json::to_value(value).map_err(|e| {
        tracing::error!("{context}: serialise to JSON failed: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "internal server error: response serialisation failed"})),
        )
            .into_response()
    })
}

#[cfg(test)]
mod tests {
    //! Coverage for the handler error-sanitization helpers. Each branch
    //! of `sanitize_bulk_row_error` is pinned, and each response builder
    //! is driven through `IntoResponse` so the status + sanitized body
    //! are verified end-to-end (the bodies must NEVER echo the raw inner
    //! error string).

    use super::{
        bad_request_opaque, governance_error_500, handler_error_500, internal_error_response,
        sanitize_bulk_row_error, to_value_or_500,
    };
    use axum::http::StatusCode;

    async fn body_string(resp: axum::response::Response) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("collect body");
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    #[test]
    fn sanitize_classifies_each_allowlisted_bucket() {
        // Validation family — every trigger substring maps to the same label.
        for raw in [
            "title cannot be empty",
            "content exceeds max length",
            "id has invalid characters",
            "tag has invalid control characters",
            "priority must be 1-10",
            "namespace is required",
        ] {
            assert_eq!(
                sanitize_bulk_row_error(raw),
                "validation failed",
                "validation trigger {raw:?} must classify as validation failed"
            );
        }
        assert_eq!(
            sanitize_bulk_row_error("title already exists in namespace alpha"),
            "conflict: already exists"
        );
        assert_eq!(
            sanitize_bulk_row_error("UNIQUE constraint failed: memories.id"),
            "conflict: already exists"
        );
        assert_eq!(
            sanitize_bulk_row_error("memory abc123 not found"),
            "not found"
        );
        assert_eq!(
            sanitize_bulk_row_error("write denied by governance policy"),
            "forbidden"
        );
        assert_eq!(
            sanitize_bulk_row_error("permission check failed"),
            "forbidden"
        );
        assert_eq!(
            sanitize_bulk_row_error("quorum not met for namespace"),
            "replication unavailable"
        );
        assert_eq!(
            sanitize_bulk_row_error("fanout to peer host:bob failed"),
            "replication unavailable"
        );
        assert_eq!(
            sanitize_bulk_row_error("peer host:bob unreachable"),
            "replication unavailable"
        );
        // Unmatched → safe default; must NOT echo the raw SQL/path detail.
        let raw = "near \"SELECT\": syntax error in /var/db/ai-memory.db";
        let label = sanitize_bulk_row_error(raw);
        assert_eq!(label, "internal error");
        assert!(
            !label.contains("SELECT") && !label.contains("/var/db"),
            "default label must not leak the raw inner detail"
        );
    }

    #[tokio::test]
    async fn internal_error_response_is_sanitized_500() {
        let resp = internal_error_response("ctx", &"raw sql leak DROP TABLE memories");
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.contains("DROP TABLE"), "body must not echo raw error");
        assert!(body.contains("error"));
    }

    #[tokio::test]
    async fn handler_error_500_is_sanitized() {
        let resp = handler_error_500(&"rusqlite: database is locked at /secret/path.db");
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.contains("/secret/path"));
    }

    #[tokio::test]
    async fn governance_error_500_is_sanitized() {
        let resp = governance_error_500(&"rule provider timeout details");
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.contains("timeout details"));
        assert!(body.contains("error"));
    }

    #[tokio::test]
    async fn bad_request_opaque_is_400_and_opaque() {
        let resp = bad_request_opaque("ctx", &"INSERT INTO memories raw text");
        let (status, body) = body_string(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!body.contains("INSERT INTO"));
        assert_eq!(body, r#"{"error":"invalid request"}"#);
    }

    #[test]
    fn to_value_or_500_ok_on_serializable() {
        let v = to_value_or_500("ctx", &serde_json::json!({"k": 1})).expect("serializes");
        assert_eq!(v["k"], 1);
    }

    #[tokio::test]
    async fn to_value_or_500_err_on_non_string_map_key() {
        use std::collections::HashMap;
        // serde_json fails to serialise a map with non-string keys.
        let mut m: HashMap<Vec<u8>, i32> = HashMap::new();
        m.insert(vec![1, 2, 3], 9);
        let err = to_value_or_500("ctx", &m).expect_err("non-string key must fail");
        let (status, body) = body_string(err).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("serialisation failed"));
    }
}
