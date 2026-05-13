// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! MCP `memory_reflection_origin` handler.
//!
//! v0.7.0 Wave-2 fix B2 (S6-M1) — introspection surface over
//! `metadata.peer_origin`. Given a memory id, returns the cross-peer
//! attribution block the federation receive path stamped at import
//! time, plus the local depth-at-arrival snapshot. Locally-minted
//! memories return `peer_origin: null` so callers can branch on
//! "imported vs minted-here".

use serde_json::{Value, json};

/// MCP handler — single-shot lookup. Returns
/// `{memory_id, peer_origin, signing_agent, original_depth,
/// local_depth_at_arrival}` (see
/// [`crate::federation::reflection_bookkeeping::ReflectionOrigin`] for
/// the canonical struct shape).
///
/// Errors:
///   * `"memory_id is required (string)"` — missing or wrong-typed.
///   * `"memory not found: <id>"` — no row matches.
///   * `"<sql error>"` — substrate failure (surfaced verbatim).
pub fn handle_reflection_origin(
    conn: &rusqlite::Connection,
    params: &Value,
) -> Result<Value, String> {
    let memory_id = params
        .get("memory_id")
        .and_then(Value::as_str)
        .ok_or("memory_id is required (string)")?;
    match crate::federation::reflection_bookkeeping::lookup_reflection_origin(conn, memory_id) {
        Ok(Some(origin)) => Ok(json!({
            "memory_id": origin.memory_id,
            "peer_origin": origin.peer_origin,
            "signing_agent": origin.signing_agent,
            "original_depth": origin.original_depth,
            "local_depth_at_arrival": origin.local_depth_at_arrival,
        })),
        Ok(None) => Err(format!("memory not found: {memory_id}")),
        Err(e) => Err(e.to_string()),
    }
}
