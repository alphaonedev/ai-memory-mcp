// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #9616 — THE one reader of the `X-Agent-Id` header on the HTTP
//! surface, and the one place an HTTP caller is resolved from it.
//!
//! Before #9616 every handler read the header with
//! `headers.get(X-Agent-Id).and_then(|v| v.to_str().ok())` and resolved it
//! with `resolve_http_agent_id(..).unwrap_or_else(|_| <fallback>)`. Three
//! defects followed from that shape:
//!
//! * a header that is not valid UTF-8 was read as ABSENT, so the request was
//!   served as a fresh anonymous caller instead of being refused;
//! * a request carrying two `X-Agent-Id` headers was served as whichever
//!   came first, so two layers could judge two different principals;
//! * an invalid header fell back to a sentinel at 26 sites, and on the
//!   postgres `DELETE /api/v1/memories/{id}` arm to the NAMED principal
//!   `ai:http`.
//!
//! This module fails closed on all three: every form that is not one
//! well-formed identity is a [`CallerRefusal`], a `400` whose `error` is
//! `invalid agent_id: <reason>` on every route and both backends. The
//! missing header keeps its documented anonymous default
//! (`docs/API_REFERENCE.md`), resolved by
//! [`crate::identity::resolve_http_agent_id`].
//!
//! `tests/agent_id_refusal_9616.rs` holds the per-route, per-backend census
//! and the source ratchet that keeps every header read under `src/handlers`
//! inside this module.

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// The field name every refusal is reported under.
pub const AGENT_ID_FIELD: &str = "agent_id";

/// Reason for a header whose bytes are not UTF-8.
pub const NON_UTF8_REASON: &str = "X-Agent-Id header is not valid UTF-8";

/// Reason for a request carrying more than one `X-Agent-Id` header.
pub const MULTIPLE_REASON: &str = "more than one X-Agent-Id header";

/// A refused caller identity: the full `invalid agent_id: <reason>` message.
/// Its response is a `400` with that message as `error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerRefusal(String);

impl CallerRefusal {
    fn new(reason: impl std::fmt::Display) -> Self {
        Self(crate::errors::msg::invalid(AGENT_ID_FIELD, reason))
    }

    /// The `invalid agent_id: <reason>` message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CallerRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl IntoResponse for CallerRefusal {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(json!({"error": self.0}))).into_response()
    }
}

/// The `X-Agent-Id` header as text: `Ok(None)` when absent, `Ok(Some(..))`
/// for exactly one UTF-8 value (shape is validated by the resolver, not
/// here).
///
/// # Errors
/// A [`CallerRefusal`] when the header appears more than once or its bytes
/// are not UTF-8.
pub fn header_agent_id(headers: &HeaderMap) -> Result<Option<&str>, CallerRefusal> {
    let mut values = headers.get_all(crate::HEADER_AGENT_ID).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(CallerRefusal::new(MULTIPLE_REASON));
    }
    first
        .to_str()
        .map(Some)
        .map_err(|_| CallerRefusal::new(NON_UTF8_REASON))
}

/// Resolve the HTTP caller from the header, with an optional body-side
/// claim that must agree with it (see
/// [`crate::identity::resolve_http_agent_id`]).
///
/// # Errors
/// A [`CallerRefusal`] for every unusable header form and for a body claim
/// that is malformed or disagrees with the header.
pub fn resolve_caller(headers: &HeaderMap, body: Option<&str>) -> Result<String, CallerRefusal> {
    let header = header_agent_id(headers)?;
    crate::identity::resolve_http_agent_id(body, header).map_err(CallerRefusal::new)
}

/// [`resolve_caller`] with no body claim, refusal already rendered: the form
/// a handler uses at its top (`match http_caller(&headers) { Ok(c) => c,
/// Err(r) => return r }`).
///
/// # Errors
/// The `400` refusal response.
pub fn http_caller(headers: &HeaderMap) -> Result<String, Response> {
    resolve_caller(headers, None).map_err(IntoResponse::into_response)
}

/// [`http_caller`] for an inner function whose headers are optional: an
/// in-process call with no headers is the anonymous default, exactly as an
/// HTTP request with no `X-Agent-Id` header.
///
/// # Errors
/// The `400` refusal response.
pub fn http_caller_in(headers: Option<&HeaderMap>) -> Result<String, Response> {
    match headers {
        Some(headers) => http_caller(headers),
        None => resolve_caller(&HeaderMap::new(), None).map_err(IntoResponse::into_response),
    }
}

/// The actor to RECORD on an audit row that is written on a refusal path,
/// where the request is already being refused for another reason: the
/// resolved caller, or the `anonymous:invalid` sentinel when the header is
/// unusable. Never an authority decision; a label only.
#[must_use]
pub fn audit_actor(headers: &HeaderMap) -> String {
    resolve_caller(headers, None)
        .unwrap_or_else(|_| crate::identity::sentinels::ANONYMOUS_INVALID.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn with(values: &[&[u8]]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for v in values {
            headers.append(
                crate::HEADER_AGENT_ID,
                HeaderValue::from_bytes(v).expect("legal header bytes"),
            );
        }
        headers
    }

    #[test]
    fn absent_header_is_the_documented_anonymous_default_9616() {
        let caller = resolve_caller(&HeaderMap::new(), None).expect("anonymous default");
        assert!(
            crate::identity::is_anonymous_request_id(&caller),
            "{caller}"
        );
    }

    #[test]
    fn one_valid_header_is_the_caller_9616() {
        assert_eq!(
            resolve_caller(&with(&[b"ai:alice"]), None).as_deref(),
            Ok("ai:alice")
        );
    }

    #[test]
    fn every_invalid_form_is_one_named_refusal_9616() {
        let cases: &[(&[&[u8]], &str)] = &[
            (&[b"ai:\xffx"], NON_UTF8_REASON),
            (&[b"ai:a", b"ai:b"], MULTIPLE_REASON),
            (&[b"ai:a", b"ai:a"], MULTIPLE_REASON),
        ];
        for (values, reason) in cases {
            let refusal = resolve_caller(&with(values), None).expect_err("refused");
            assert_eq!(
                refusal.message(),
                crate::errors::msg::invalid(AGENT_ID_FIELD, reason)
            );
        }
        for bad in [&b"bad id"[..], b"daemon", &[b'a'; 129][..]] {
            let refusal = resolve_caller(&with(&[bad]), None).expect_err("refused");
            assert!(
                refusal.message().starts_with("invalid agent_id: "),
                "{refusal}"
            );
        }
    }

    #[test]
    fn body_claim_must_match_the_header_9616() {
        let refusal = resolve_caller(&with(&[b"ai:alice"]), Some("ai:bob")).expect_err("mismatch");
        assert!(
            refusal.message().contains("agent_id_body_header_mismatch"),
            "{refusal}"
        );
    }

    /// Size and time bound: a request with as many `X-Agent-Id` headers as a
    /// `HeaderMap` holds is refused at the second value, and a 100K-byte
    /// value is refused by the length check, each well inside one second.
    #[test]
    fn oversized_inputs_are_refused_in_bounded_time_9616() {
        /// Below the `HeaderMap` capacity ceiling (32768 entries).
        const MANY_HEADERS: usize = 30_000;
        const HUGE_VALUE: usize = 100_000;
        let bound = std::time::Duration::from_secs(1);
        let mut headers = HeaderMap::new();
        for _ in 0..MANY_HEADERS {
            headers.append(crate::HEADER_AGENT_ID, HeaderValue::from_static("ai:a"));
        }
        let start = std::time::Instant::now();
        let refusal = header_agent_id(&headers).expect_err("refused");
        assert!(start.elapsed() < bound);
        assert!(refusal.message().ends_with(MULTIPLE_REASON), "{refusal}");

        let huge = vec![b'a'; HUGE_VALUE];
        let start = std::time::Instant::now();
        let refusal = resolve_caller(&with(&[&huge]), None).expect_err("refused");
        assert!(start.elapsed() < bound);
        assert!(refusal.message().starts_with("invalid agent_id: "));
        assert!(
            refusal.message().len() < HUGE_VALUE,
            "the refusal must not echo the whole value"
        );
    }
}
