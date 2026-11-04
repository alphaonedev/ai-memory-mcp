// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8497 (umbrella #8493) — the ONE owner rule for `entity_register`.
//!
//! An entity row is owned by the VERIFIED caller, never by a value the caller
//! writes. Before #8497 the MCP tool resolved the owner through the unbound
//! ladder (wire `agent_id` beat `AI_MEMORY_AGENT_ID`), the HTTP route preferred
//! the body `agent_id` over the `X-Agent-Id` header, and the postgres funnel
//! `or_insert`-ed the owner so an inline `metadata.agent_id` won. This module
//! is the shared rule every entry point and both `MemoryStore` backends call,
//! so the two backends cannot disagree (CLAUDE.md "Database operation").
//!
//! A claimed owner (wire `agent_id`, or an inline `metadata.agent_id`) that
//! differs from the verified subject is REFUSED, and the refusal is written to
//! the audit trail (outcome `deny`), per ERRORS-01 / ERRORS-19.

use serde_json::Value;

/// Operation name carried in refusal text and audit rows.
pub const OP_ENTITY_REGISTER: &str = "entity_register";

/// A claimed entity owner that disagrees with the verified subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityOwnerMismatch {
    /// Which claim disagreed: `agent_id` or `metadata.agent_id`.
    pub field: &'static str,
    /// The verified subject the entity would have been owned by.
    pub subject: String,
    /// The refused claim, rendered for the refusal text.
    pub claimed: String,
}

impl std::fmt::Display for EntityOwnerMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "agent_id mismatch: caller '{}' may only {OP_ENTITY_REGISTER} as itself \
             ({} '{}')",
            self.subject, self.field, self.claimed
        )
    }
}

impl std::error::Error for EntityOwnerMismatch {}

/// Check the claimed owners against the verified `subject`.
///
/// `claimed_agent_id` is the wire `agent_id` (empty counts as absent, the
/// `resolve_governance_subject` rule). A present `metadata.agent_id` of any
/// JSON type other than null that is not exactly the subject string is also a
/// refusal: the owner stamp is forced to the subject, so a differing inline
/// value is a forgery attempt, not a hint.
///
/// # Errors
/// [`EntityOwnerMismatch`] naming the first disagreeing claim.
pub fn check_entity_owner_claims(
    subject: &str,
    claimed_agent_id: Option<&str>,
    extra_metadata: &Value,
) -> Result<(), EntityOwnerMismatch> {
    if let Some(claimed) = claimed_agent_id.filter(|s| !s.is_empty())
        && claimed != subject
    {
        return Err(EntityOwnerMismatch {
            field: "agent_id",
            subject: subject.to_string(),
            claimed: claimed.to_string(),
        });
    }
    match extra_metadata.get("agent_id") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) if s == subject => {}
        Some(other) => {
            return Err(EntityOwnerMismatch {
                field: "metadata.agent_id",
                subject: subject.to_string(),
                claimed: other
                    .as_str()
                    .map_or_else(|| other.to_string(), str::to_string),
            });
        }
    }
    Ok(())
}

/// Write the refusal to the audit trail (outcome `deny`). A no-op when the
/// trail is not configured; an emit failure never changes the refusal.
pub fn audit_entity_owner_refusal(
    mismatch: &EntityOwnerMismatch,
    namespace: &str,
    canonical_name: &str,
    synthesis_source: &str,
) {
    crate::audit::emit(
        crate::audit::EventBuilder::new(
            crate::audit::AuditAction::Store,
            crate::audit::actor(mismatch.subject.clone(), synthesis_source, None),
            crate::audit::target_memory(
                "*",
                namespace,
                Some(canonical_name.to_string()),
                None,
                None,
            ),
        )
        .error(format!("{OP_ENTITY_REGISTER}: {mismatch}"))
        .outcome(crate::audit::AuditOutcome::Deny),
    );
}

/// [`check_entity_owner_claims`] plus the audit row on refusal. The single
/// call every entry point and both backends make.
///
/// # Errors
/// [`EntityOwnerMismatch`] (already audited).
pub fn enforce_entity_owner(
    subject: &str,
    claimed_agent_id: Option<&str>,
    extra_metadata: &Value,
    namespace: &str,
    canonical_name: &str,
    synthesis_source: &str,
) -> Result<(), EntityOwnerMismatch> {
    check_entity_owner_claims(subject, claimed_agent_id, extra_metadata).inspect_err(|m| {
        audit_entity_owner_refusal(m, namespace, canonical_name, synthesis_source);
    })
}

/// SAL-trait owner rule shared by `SqliteStore` and `PostgresStore`: the owner
/// is the caller context's principal (`ctx_agent_id`). A differing `agent_id`
/// argument or inline `metadata.agent_id` is refused (and audited). Returns the
/// owner to stamp.
///
/// # Errors
/// [`EntityOwnerMismatch`] (already audited).
pub fn trait_entity_owner(
    ctx_agent_id: &str,
    agent_id_arg: Option<&str>,
    extra_metadata: &Value,
    namespace: &str,
    canonical_name: &str,
) -> Result<String, EntityOwnerMismatch> {
    enforce_entity_owner(
        ctx_agent_id,
        agent_id_arg,
        extra_metadata,
        namespace,
        canonical_name,
        crate::audit::synthesis_sources::EXPLICIT,
    )?;
    Ok(ctx_agent_id.to_string())
}

/// MCP owner resolution: the verified governance subject, with the audit row
/// when a wire `agent_id` disagrees with the process principal.
///
/// # Errors
/// The [`super::resolve_governance_subject`] refusal text.
pub fn resolve_entity_owner_subject(
    explicit_agent_id: Option<&str>,
    mcp_client: Option<&str>,
    namespace: &str,
    canonical_name: &str,
) -> Result<String, String> {
    super::resolve_governance_subject(explicit_agent_id, mcp_client, OP_ENTITY_REGISTER).map_err(
        |e| {
            if let (Some(caller), Some(requested)) = (
                super::resolve_read_visibility_caller(),
                explicit_agent_id.filter(|s| !s.is_empty()),
            ) && caller != requested
            {
                audit_entity_owner_refusal(
                    &EntityOwnerMismatch {
                        field: "agent_id",
                        subject: caller,
                        claimed: requested.to_string(),
                    },
                    namespace,
                    canonical_name,
                    crate::audit::synthesis_sources::EXPLICIT,
                );
            }
            e.to_string()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matching_and_absent_claims_pass() {
        assert!(check_entity_owner_claims("ai:x", None, &json!({})).is_ok());
        assert!(check_entity_owner_claims("ai:x", Some(""), &json!({})).is_ok());
        assert!(
            check_entity_owner_claims("ai:x", Some("ai:x"), &json!({"agent_id": "ai:x"})).is_ok()
        );
        assert!(check_entity_owner_claims("ai:x", None, &json!({"agent_id": null})).is_ok());
    }

    #[test]
    fn differing_wire_or_inline_claim_is_refused() {
        let wire = check_entity_owner_claims("ai:x", Some("ai:y"), &json!({})).unwrap_err();
        assert_eq!(wire.field, "agent_id");
        let inline =
            check_entity_owner_claims("ai:x", None, &json!({"agent_id": "ai:y"})).unwrap_err();
        assert_eq!(inline.field, "metadata.agent_id");
        let non_string =
            check_entity_owner_claims("ai:x", None, &json!({"agent_id": 7})).unwrap_err();
        assert_eq!(non_string.claimed, "7");
    }
}
