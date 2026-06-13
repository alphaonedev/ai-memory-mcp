// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1579 B4 — HTTP response-format negotiation for the recall/search
//! surfaces.
//!
//! MCP has shipped the TOON encoder since v0.6.x (default
//! `toon_compact`, ~79% smaller than the JSON envelope on memory
//! rows); this module exposes the SAME encoder paths
//! ([`crate::toon::memories_to_toon`] / [`crate::toon::search_to_toon`])
//! over HTTP via the `format` query/body parameter:
//!
//! - `format=json` (or omitted) — the legacy `application/json`
//!   envelope, byte-identical to pre-#1579 responses.
//! - `format=toon` — non-compact TOON, served `text/plain`.
//! - `format=toon_compact` — compact TOON, served `text/plain`.
//!
//! Invalid values are rejected with `400` carrying the SSOT message
//! from [`crate::toon::invalid_format_msg`] — the handlers call
//! [`crate::toon::WireFormat::parse_http`] BEFORE doing any work.

use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::Value;

use crate::toon::{self, WireFormat};

/// Serialize a recall/list-shaped payload (`"memories"` array) per the
/// negotiated format. TOON variants return `text/plain; charset=utf-8`
/// (axum's `String` responder); JSON keeps the legacy envelope.
pub(crate) fn memories_response(format: WireFormat, payload: Value) -> Response {
    match format {
        WireFormat::Json => Json(payload).into_response(),
        WireFormat::Toon => toon::memories_to_toon(&payload, false).into_response(),
        WireFormat::ToonCompact => toon::memories_to_toon(&payload, true).into_response(),
    }
}

/// Serialize a search-shaped payload (`"results"` array) per the
/// negotiated format. Same content-type contract as
/// [`memories_response`].
pub(crate) fn search_response(format: WireFormat, payload: Value) -> Response {
    match format {
        WireFormat::Json => Json(payload).into_response(),
        WireFormat::Toon => toon::search_to_toon(&payload, false).into_response(),
        WireFormat::ToonCompact => toon::search_to_toon(&payload, true).into_response(),
    }
}

/// The `400` rejection for an unparseable `format` parameter; `msg` is
/// the SSOT string [`WireFormat::parse_http`] produced.
pub(crate) fn invalid_format_response(msg: &str) -> Response {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}
