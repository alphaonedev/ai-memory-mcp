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

/// Names the operation in the #3363 caller-binding refusal raised by
/// [`resolve_actor`]. One literal, shared by every coordination create surface
/// that funnels through this helper (pm-v3.1 no-scattered-literal gate).
const ACTOR_OP: &str = "create coordination objects";

/// Resolve the ambient coordination actor for a create surface: validate a
/// caller-supplied `agent_id` (rejecting shape violations + the reserved
/// internal sentinels + whitespace / control chars) and, when none is
/// supplied, fall back to the durable process identity so the write is ALWAYS
/// attributed and quota-charged (closing the #2998 "omit agent_id ⇒ uncharged
/// + unbounded" opt-in-by-attacker gap). Mirrors the `check_agent_action`
/// ambient-caller precedent.
///
/// #3363 — BOUND to the enforced caller. `identity::resolve_agent_id` gives the
/// EXPLICIT wire value precedence over the `AI_MEMORY_AGENT_ID` env identity, so
/// pre-#3363 a caller running as `ai:realcaller` could post
/// `memory_action_create {agent_id: "ai:bob"}` and have the row attributed to —
/// and bob's per-namespace storage quota charged for — a principal it is not.
/// Routed through [`crate::identity::resolve_governance_subject`], a wire value
/// that disagrees with the enforced caller is now REFUSED (fail-closed, same
/// error class as the #3171 fixes on the other fourteen tools), and the
/// single-operator default (env unset) stays byte-identical.
///
/// # Errors
/// A stringified failure when a caller-supplied `agent_id` is shape-invalid or
/// reserved, when it disagrees with the enforced caller, or when identity
/// resolution fails outright.
pub fn resolve_actor(caller_supplied: Option<&str>) -> Result<String, String> {
    let cleaned = caller_supplied.map(str::trim).filter(|s| !s.is_empty());
    crate::identity::resolve_governance_subject(cleaned, None, ACTOR_OP).map_err(|e| {
        let msg = e.to_string();
        // The #3363 binding refusal is already self-describing
        // ("agent_id mismatch: caller '…' may only …"); only the shape /
        // reserved-sentinel failures keep the #2998 "invalid agent_id" prefix,
        // so neither error contract changes and neither reads doubled.
        if msg.starts_with("agent_id mismatch") {
            msg
        } else {
            format!("invalid agent_id: {msg}")
        }
    })
}

/// Validate and screen an action through the shared direct/routine create boundary.
/// Returns the validated action and its #1807 storage-only charge.
///
/// # Errors
/// Refuses invalid fields, credentials, metadata, or actor attribution.
pub(crate) fn prepare_action(
    mut action: crate::models::Action,
) -> Result<(crate::models::Action, i64), String> {
    require_namespace(&action.namespace)?;
    require_text("title", &action.title, MAX_TEXT_FIELD_BYTES)?;
    require_text("kind", &action.kind, MAX_KIND_BYTES)?;
    require_payload_size("payload", &action.payload)?;
    action.agent_id = Some(resolve_actor(action.agent_id.as_deref())?);
    crate::secret_screen::screen_text_field_for_caller(&mut action.title)
        .map_err(|e| e.to_string())?;
    crate::secret_screen::screen_json_field_for_caller(&mut action.payload)
        .map_err(|e| e.to_string())?;
    if !action.metadata.is_null() {
        crate::secret_screen::screen_json_field_for_caller(&mut action.metadata)
            .map_err(|e| e.to_string())?;
        crate::validate::validate_metadata(&action.metadata).map_err(|e| e.to_string())?;
    }
    let bytes = crate::quotas::coordination_payload_bytes(
        &[&action.title, &action.kind],
        &[&action.payload, &action.metadata],
    );
    Ok((action, bytes))
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
    fn resolve_actor_binds_to_the_enforced_caller_3363() {
        // #3363 — the coordination create funnel (`action_create`,
        // `routine_create`, `checkpoint_create`) took the wire `agent_id` /
        // `created_by` verbatim because `identity::resolve_agent_id` gives the
        // EXPLICIT value precedence over `AI_MEMORY_AGENT_ID`. Under the
        // multi-tenant posture a disagreeing wire principal must now refuse
        // (fail-closed) rather than attribute — and charge the quota of — a
        // principal the caller is not.
        let _envg = crate::identity::agent_id_env_test_lock();
        // SAFETY: process-global env mutation serialised on the crate-wide
        // test lock held above; every mutator takes the same lock.
        unsafe { std::env::set_var("AI_MEMORY_AGENT_ID", "ai:realcaller") };

        // DENIED — a differing wire principal.
        let err = resolve_actor(Some("ai:bob")).expect_err("a forged actor must refuse");
        assert!(
            err.contains("agent_id mismatch") && err.contains("ai:bob"),
            "got: {err}"
        );
        // The refusal message is not doubled with the #2998 shape prefix.
        assert!(!err.contains("invalid agent_id"), "got: {err}");

        // ALLOWED — the enforced caller acting as itself, and the omitted case
        // (#2998 always-attributed) resolving to that same caller.
        assert_eq!(
            resolve_actor(Some("ai:realcaller")).expect("self is allowed"),
            "ai:realcaller"
        );
        assert_eq!(
            resolve_actor(None).expect("ambient resolves"),
            "ai:realcaller"
        );

        // SAFETY: same serialisation as the set above.
        unsafe { std::env::remove_var("AI_MEMORY_AGENT_ID") };
    }

    #[test]
    fn resolve_actor_validates_caller_and_falls_back() {
        // #3363 — this assertion depends on the single-operator posture
        // (`AI_MEMORY_AGENT_ID` unset), where the legacy ladder still honours a
        // valid wire value byte-identically.
        let _envg = crate::identity::agent_id_env_unset_guard();
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
