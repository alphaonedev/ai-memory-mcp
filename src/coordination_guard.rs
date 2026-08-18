// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2994 / #2998 — caller-origin input guards shared by the coordination write
//! plane (actions / signals / checkpoints / routines).
//!
//! The coordination create surfaces insert caller content DIRECTLY via the
//! `crate::{actions,signals,checkpoints,routines}` free-functions, bypassing
//! the memory-lane `validate::validate_*` + storage-funnel screen the memory
//! write path enjoys. Before #2998 they accepted an empty / `../../etc/passwd`
//! namespace, an empty title+kind, a 200k-char title, a 2 MB payload, and an
//! `agent_id` carrying spaces + newlines that flowed verbatim into the
//! `coordination_audit` identity fields (log injection). Quota was
//! opt-in-by-attacker: omit `agent_id` and the create was uncharged AND
//! unbounded. These guards are the ONE place those bounds live so every create
//! surface (MCP today, any future HTTP surface) enforces the same limits and is
//! always attributed to a validated principal.

use serde_json::Value;

/// Shared error message for a `now + ttl_secs` overflow — referenced by every
/// coordination surface that computes an `expires_at` from a caller `ttl_secs`
/// (MCP lease acquire/renew + signal send, HTTP signal send), so the literal
/// lives at ONE site (pm-v3.1 no-scattered-literal gate).
pub const TTL_SECS_OVERFLOW: &str = "ttl_secs overflow";

/// Max bytes for a coordination title / name / subject text field. Stored
/// cleartext, FTS-indexed, and (for signals) federated, so a hard byte cap
/// bounds the write regardless of the per-agent storage quota.
pub const MAX_TEXT_FIELD_BYTES: usize = 8192;

/// Max bytes for a coordination `kind` discriminator.
pub const MAX_KIND_BYTES: usize = 256;

/// Max serialized bytes for a coordination JSON payload / body / condition /
/// template — mirrors the metadata size ceiling the memory lane enforces
/// (`crate::validate::validate_metadata`).
pub const MAX_PAYLOAD_BYTES: usize = 65_536;

/// Validate a coordination namespace via the shared memory-lane rule — rejects
/// empty, whitespace, backslash / null bytes, control chars, path-traversal
/// (`.` / `..`) segments, and over-depth / over-length hierarchical paths.
///
/// # Errors
/// A stringified [`crate::validate::validate_namespace`] failure.
pub fn require_namespace(ns: &str) -> Result<(), String> {
    crate::validate::validate_namespace(ns).map_err(|e| e.to_string())
}

/// Require a non-empty text field within `max` bytes, free of control
/// characters (a `\n` / `\t` is tolerated, matching the memory-lane
/// `is_clean_string` rule; a bare CR / NUL / escape is a log-injection vector
/// into the `coordination_audit` identity fields and is rejected). `field`
/// names the field for the error message.
///
/// # Errors
/// A stringified emptiness / over-size / control-char failure.
pub fn require_text(field: &str, value: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.len() > max {
        return Err(format!("{field} exceeds the {max}-byte limit"));
    }
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(format!("{field} contains invalid control characters"));
    }
    Ok(())
}

/// Bound the serialized size of a coordination JSON field (payload / body /
/// condition / template). A `Null` field is unbounded-free (it is the
/// "absent" sentinel). `field` names the field for the error message.
///
/// # Errors
/// A stringified over-size failure.
pub fn require_payload_size(field: &str, value: &Value) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let bytes = value.to_string().len();
    if bytes > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "{field} exceeds the {MAX_PAYLOAD_BYTES}-byte limit"
        ));
    }
    Ok(())
}

/// Resolve the ambient coordination actor for a create surface: validate a
/// caller-supplied `agent_id` (rejecting shape violations + the reserved
/// internal sentinels + whitespace / control chars) and, when none is
/// supplied, fall back to the durable process identity so the write is ALWAYS
/// attributed and quota-charged (closing the #2998 "omit agent_id ⇒ uncharged
/// + unbounded" opt-in-by-attacker gap). Mirrors the `check_agent_action`
/// ambient-caller precedent.
///
/// # Errors
/// A stringified failure when a caller-supplied `agent_id` is shape-invalid or
/// reserved, or when identity resolution fails outright.
pub fn resolve_actor(caller_supplied: Option<&str>) -> Result<String, String> {
    let cleaned = caller_supplied.map(str::trim).filter(|s| !s.is_empty());
    crate::identity::resolve_agent_id(cleaned, None).map_err(|e| format!("invalid agent_id: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn require_namespace_rejects_empty_and_traversal() {
        assert!(require_namespace("").is_err());
        assert!(require_namespace("../../etc/passwd").is_err());
        assert!(require_namespace("team/ops").is_ok());
        assert!(require_namespace("_act").is_ok());
    }

    #[test]
    fn require_text_rejects_empty_oversize_and_control() {
        assert!(require_text("title", "  ", MAX_TEXT_FIELD_BYTES).is_err());
        assert!(
            require_text(
                "title",
                &"x".repeat(MAX_TEXT_FIELD_BYTES + 1),
                MAX_TEXT_FIELD_BYTES
            )
            .is_err()
        );
        assert!(require_text("agent_id", "has\rcarriage", MAX_TEXT_FIELD_BYTES).is_err());
        assert!(require_text("title", "normal title", MAX_TEXT_FIELD_BYTES).is_ok());
    }

    #[test]
    fn require_payload_size_bounds_serialized_bytes() {
        assert!(require_payload_size("payload", &Value::Null).is_ok());
        assert!(require_payload_size("payload", &json!({"k": "v"})).is_ok());
        let big = "x".repeat(MAX_PAYLOAD_BYTES);
        assert!(require_payload_size("payload", &json!({ "big": big })).is_err());
    }

    #[test]
    fn resolve_actor_validates_caller_and_falls_back() {
        // A shape-invalid caller value is rejected (log-injection / spoof guard).
        assert!(resolve_actor(Some("has spaces;DROP")).is_err());
        // Omitted actor resolves to a durable non-empty ambient id.
        let ambient = resolve_actor(None).expect("ambient resolves");
        assert!(!ambient.is_empty());
        // A valid caller value is preserved.
        assert_eq!(
            resolve_actor(Some("ai:worker-1")).expect("valid"),
            "ai:worker-1"
        );
    }
}
