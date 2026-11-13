// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8771 / #8772 / #8774 / #8775 — the ONE owner gate for mutations of
//! stored non-memory objects (skill lineages, routines, agent roster
//! entries). Refs #8741.
//!
//! ## The class it closes
//!
//! A mutating operation acted on a target row without checking the target's
//! recorded owner against the authenticated principal: agent B retired,
//! unretired, purged or superseded agent A's skill, froze A's routine, and
//! re-registered A's roster identity.
//!
//! ## The rule (owner-only)
//!
//! [`authorize_owner_mutation`] admits a mutation only when
//!
//! * the principal is [`MutationPrincipal::Unbound`] — no process identity is
//!   configured (`AI_MEMORY_AGENT_ID` unset), the single-operator trust
//!   posture every memory funnel keeps (#1786 precedent: the gate fires only
//!   on the multi-tenant opt-in);
//! * the principal is [`MutationPrincipal::Granted`] — the caller already
//!   passed a shipped governance gate for the object (the HTTP skill routes'
//!   `require_admin`);
//! * the principal is the daemon sentinel (the
//!   `visibility::caller_owns_for_mutation` pass-through); or
//! * [`owner_stamp::metadata_admits_mutation`] admits the caller against the
//!   object's owner stamp — owned by the caller, or unstamped under the
//!   shipped #3124 `AI_MEMORY_UNSTAMPED_MUTATION` posture (warn admits and
//!   counts, refuse refuses). A malformed stamp is always refused.
//!
//! Anything else is refused with the ONE text
//! [`crate::errors::msg::CALLER_DOES_NOT_OWN_OBJECT`] and a `deny` forensic
//! row. The principal is always the resolved caller, never a body- or
//! argument-supplied `agent_id`.
//!
//! decision: owner-only now, over owner-or-governance-approval, because the
//! tighter posture can be widened later without a break; widening is a
//! change to this one function.

use serde_json::{Value, json};

use crate::identity::owner_stamp::{self, MutationSite};

/// Funnel labels for the #3124 observability counter (closed set).
pub mod funnel {
    /// `memory_skill_register` superseding an existing lineage head (#8772).
    pub const SKILL_SUPERSEDE: &str = "skill_supersede";
    /// `memory_skill_retire` (retire and unretire, #8771).
    pub const SKILL_RETIRE: &str = "skill_retire";
    /// `memory_skill_delete` (#8771).
    pub const SKILL_DELETE: &str = "skill_delete";
    /// `memory_routine_freeze` (#8774).
    pub const ROUTINE_FREEZE: &str = "routine_freeze";
    /// `memory_agent_register` re-registering an existing identity (#8775).
    pub const AGENT_REGISTER: &str = "agent_register";
    /// `memory_entity_register` merging aliases into an existing entity (#8557).
    pub const ENTITY_REGISTER: &str = "entity_register";
    /// `memory_action_add_edge` touching an existing action (#8790).
    pub const ACTION_ADD_EDGE: &str = "action_add_edge";
}

/// The `StoreError::PermissionDenied.action` both SAL adapters return for an
/// owner refusal, so SQLite and PostgreSQL give one envelope.
pub const OWNER_GATE_ACTION: &str = "owner_mutation";

/// The one owner-gate refusal (#8771). Its `Display` is
/// [`crate::errors::msg::CALLER_DOES_NOT_OWN_OBJECT`]; it converts into the
/// `String` envelope of the MCP handlers (`?`) and, through
/// [`crate::errors::refusal`], into the typed `anyhow` refusal of the storage
/// funnels, so every transport renders the same text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerRefusal;

impl std::fmt::Display for OwnerRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(crate::errors::msg::CALLER_DOES_NOT_OWN_OBJECT)
    }
}

impl std::error::Error for OwnerRefusal {}

impl From<OwnerRefusal> for String {
    fn from(refusal: OwnerRefusal) -> Self {
        refusal.to_string()
    }
}

/// Who is asking to mutate a stored object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationPrincipal {
    /// No process identity configured: the single-operator trust posture.
    Unbound,
    /// The resolved (enforced) caller.
    Agent(String),
    /// The caller already holds a shipped governance grant for the object
    /// (an admin-gated HTTP route).
    Granted,
}

impl MutationPrincipal {
    /// The principal of an MCP stdio or CLI process: the enforced caller from
    /// `AI_MEMORY_AGENT_ID` (`resolve_read_visibility_caller`, env-only, so a
    /// wire `agent_id` can never select it), or [`Self::Unbound`].
    #[must_use]
    pub fn from_process_env() -> Self {
        Self::from_resolved(crate::identity::resolve_read_visibility_caller().as_deref())
    }

    /// The principal of a SAL call: [`Self::Granted`] for an operator
    /// context that already bypasses visibility, else the context's
    /// resolved caller (never an argument-supplied `agent_id`).
    #[cfg(feature = "sal")]
    #[must_use]
    pub fn from_context(ctx: &crate::store::CallerContext) -> Self {
        if ctx.bypass_visibility {
            Self::Granted
        } else {
            Self::Agent(ctx.agent_id.clone())
        }
    }

    /// The principal for an already-resolved enforced caller (`None` = the
    /// unset-identity posture).
    #[must_use]
    pub fn from_resolved(caller: Option<&str>) -> Self {
        match caller {
            Some(caller) => Self::Agent(caller.to_string()),
            None => Self::Unbound,
        }
    }
}

/// The owner metadata of an object whose owner is a plain column value
/// (`routines.created_by`, an agent roster entry's own `agent_id`), in the
/// shape [`authorize_owner_mutation`] reads.
#[must_use]
pub fn owner_metadata(owner: &str) -> Value {
    json!({ (crate::META_KEY_AGENT_ID): owner })
}

/// The owner metadata of a row whose owner stamp lives in a stored JSON
/// `metadata` TEXT column (`skills.metadata`). Text that does not parse is
/// classified MALFORMED (fail closed: never an owner a caller can match,
/// never admitted as unstamped).
#[must_use]
pub fn stored_owner_metadata(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| json!({ (crate::META_KEY_AGENT_ID): false }))
}

/// The ONE owner decision for a mutation of a stored non-memory object.
///
/// `owner_metadata` carries the object's owner stamp under
/// `metadata.agent_id` (a skill row's `metadata`, or [`owner_metadata`]);
/// `object_id` names the object on the observability counter and the
/// forensic row; `funnel` is one of the [`funnel`] consts.
///
/// # Errors
/// Returns [`crate::errors::msg::CALLER_DOES_NOT_OWN_OBJECT`] when the
/// principal is a named agent the stamp does not admit.
pub fn authorize_owner_mutation(
    principal: &MutationPrincipal,
    owner_metadata: &Value,
    object_id: &str,
    funnel: &'static str,
) -> Result<(), OwnerRefusal> {
    authorize_owner_mutation_on(
        principal,
        owner_metadata,
        object_id,
        MutationSite::sqlite(funnel),
    )
}

/// The owner metadata of a row whose owner is a NULLABLE column
/// (`actions.agent_id`): `None` is an unstamped row, decided by the shipped
/// #3124 posture.
#[must_use]
pub fn optional_owner_metadata(owner: Option<&str>) -> Value {
    owner.map_or_else(|| json!({}), owner_metadata)
}

/// [`authorize_owner_mutation`] with the backend named by `site` on the
/// #3124 counter (the PostgreSQL store passes `MutationSite::postgres`).
///
/// # Errors
/// Returns [`crate::errors::msg::CALLER_DOES_NOT_OWN_OBJECT`] when the
/// principal is a named agent the stamp does not admit.
pub fn authorize_owner_mutation_on(
    principal: &MutationPrincipal,
    owner_metadata: &Value,
    object_id: &str,
    site: MutationSite,
) -> Result<(), OwnerRefusal> {
    let funnel = site.funnel;
    let caller = match principal {
        MutationPrincipal::Unbound | MutationPrincipal::Granted => return Ok(()),
        MutationPrincipal::Agent(caller) => caller,
    };
    if caller == crate::identity::sentinels::DAEMON_PRINCIPAL
        || owner_stamp::metadata_admits_mutation(owner_metadata, object_id, caller, false, site)
    {
        return Ok(());
    }
    crate::governance::audit::record_decision(
        caller,
        "deny",
        funnel,
        "",
        crate::governance::audit::ForensicPayload::new()
            .ident("object_id", object_id)
            .label("reason", crate::errors::msg::CALLER_DOES_NOT_OWN_OBJECT),
    );
    Err(OwnerRefusal)
}

/// [`authorize_owner_mutation`] as an `anyhow` refusal for a storage funnel:
/// the typed [`crate::errors::refusal`] root keeps the ONE text on MCP
/// (`MemoryError::Refused`), and [`is_owner_refusal`] lets a SAL adapter or
/// HTTP handler map it onto the `NOT_OWNER` 403.
///
/// # Errors
/// The owner refusal of [`authorize_owner_mutation`].
pub fn authorize_stored_owner(
    principal: &MutationPrincipal,
    raw_metadata: &str,
    object_id: &str,
    funnel: &'static str,
) -> anyhow::Result<()> {
    authorize_owner_mutation(
        principal,
        &stored_owner_metadata(raw_metadata),
        object_id,
        funnel,
    )
    .map_err(crate::errors::refusal)
}

/// True when `e` is the owner refusal [`authorize_stored_owner`] raised.
#[must_use]
pub fn is_owner_refusal(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<crate::errors::OwnText>(),
        Some(crate::errors::OwnText::Refusal(m)) if m == crate::errors::msg::CALLER_DOES_NOT_OWN_OBJECT
    )
}

/// #8790 — the owner gate for a new dependency edge on the SQLite action
/// DAG: the principal must own BOTH existing endpoints. A missing endpoint
/// is left to `actions::add_edge`, which keeps its shipped answer.
///
/// decision: both endpoints over the `from` endpoint only, because every
/// edge type changes the frontier of one end or the other.
///
/// # Errors
/// The owner refusal (see [`is_owner_refusal`]) for a non-owned endpoint;
/// the storage error when an endpoint read fails.
pub fn authorize_action_edge(
    conn: &rusqlite::Connection,
    principal: &MutationPrincipal,
    from_action: &str,
    to_action: &str,
) -> anyhow::Result<()> {
    if matches!(
        principal,
        MutationPrincipal::Unbound | MutationPrincipal::Granted
    ) {
        return Ok(());
    }
    for id in [from_action, to_action] {
        if let Some(action) = crate::actions::get(conn, id)? {
            authorize_owner_mutation(
                principal,
                &optional_owner_metadata(action.agent_id.as_deref()),
                id,
                funnel::ACTION_ADD_EDGE,
            )
            .map_err(crate::errors::refusal)?;
        }
    }
    Ok(())
}

/// Stamp `metadata.agent_id` with the creating principal's identity, the
/// recorded owner [`authorize_owner_mutation`] later checks. The resolved
/// owner wins over any inline `agent_id` (the #8497 entity-owner precedent);
/// a non-object metadata value is replaced by an object carrying the stamp.
pub fn stamp_owner(metadata: &mut Value, owner: &str) {
    if !metadata.is_object() {
        *metadata = json!({});
    }
    if let Value::Object(map) = metadata {
        map.insert(crate::META_KEY_AGENT_ID.to_string(), json!(owner));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::owner_stamp::UnstampedMutationMode;

    const OWNER: &str = "ai:owner-8771";
    const OTHER: &str = "ai:other-8771";
    const OBJECT: &str = "object-8771";

    fn agent(id: &str) -> MutationPrincipal {
        MutationPrincipal::Agent(id.to_string())
    }

    #[test]
    fn owner_admitted_other_refused_with_the_one_text_8771() {
        let meta = owner_metadata(OWNER);
        assert_eq!(
            authorize_owner_mutation(&agent(OWNER), &meta, OBJECT, funnel::SKILL_RETIRE),
            Ok(())
        );
        assert_eq!(
            authorize_owner_mutation(&agent(OTHER), &meta, OBJECT, funnel::SKILL_RETIRE),
            Err(OwnerRefusal)
        );
        // The one text on every transport: the String envelope and the typed
        // anyhow refusal both render the shipped constant byte for byte.
        assert_eq!(
            String::from(OwnerRefusal),
            crate::errors::msg::CALLER_DOES_NOT_OWN_OBJECT
        );
        assert_eq!(
            crate::errors::refusal(OwnerRefusal).to_string(),
            crate::errors::msg::CALLER_DOES_NOT_OWN_OBJECT
        );
    }

    #[test]
    fn unbound_granted_and_daemon_pass_8771() {
        let meta = owner_metadata(OWNER);
        for principal in [
            MutationPrincipal::Unbound,
            MutationPrincipal::Granted,
            agent(crate::identity::sentinels::DAEMON_PRINCIPAL),
        ] {
            assert_eq!(
                authorize_owner_mutation(&principal, &meta, OBJECT, funnel::ROUTINE_FREEZE),
                Ok(()),
                "{principal:?}"
            );
        }
    }

    #[test]
    fn malformed_stamp_refused_8771() {
        for meta in [json!({"agent_id": 7}), json!({"agent_id": ["x"]})] {
            assert_eq!(
                authorize_owner_mutation(&agent(OWNER), &meta, OBJECT, funnel::SKILL_DELETE),
                Err(OwnerRefusal),
                "{meta}"
            );
        }
    }

    #[test]
    fn unstamped_follows_the_shipped_posture_8771() {
        let meta = json!({});
        let site = MutationSite::sqlite(funnel::SKILL_SUPERSEDE);
        assert!(owner_stamp::metadata_admits_mutation_with_mode(
            &meta,
            OBJECT,
            OTHER,
            false,
            site,
            UnstampedMutationMode::Warn
        ));
        assert!(!owner_stamp::metadata_admits_mutation_with_mode(
            &meta,
            OBJECT,
            OTHER,
            false,
            site,
            UnstampedMutationMode::Refuse
        ));
    }

    #[test]
    fn unparseable_stored_metadata_is_malformed_8771() {
        let meta = stored_owner_metadata("{not json");
        assert_eq!(
            authorize_owner_mutation(&agent(OWNER), &meta, OBJECT, funnel::SKILL_RETIRE),
            Err(OwnerRefusal)
        );
        assert_eq!(
            stored_owner_metadata(&owner_metadata(OWNER).to_string()),
            owner_metadata(OWNER)
        );
    }

    #[test]
    fn optional_owner_and_postgres_site_decide_the_same_8790() {
        assert_eq!(optional_owner_metadata(Some(OWNER)), owner_metadata(OWNER));
        assert_eq!(optional_owner_metadata(None), json!({}));
        let meta = optional_owner_metadata(Some(OWNER));
        for site in [
            MutationSite::sqlite(funnel::ACTION_ADD_EDGE),
            MutationSite::postgres(funnel::ENTITY_REGISTER),
        ] {
            assert_eq!(
                authorize_owner_mutation_on(&agent(OWNER), &meta, OBJECT, site),
                Ok(())
            );
            assert_eq!(
                authorize_owner_mutation_on(&agent(OTHER), &meta, OBJECT, site),
                Err(OwnerRefusal)
            );
        }
    }

    #[test]
    fn stamp_owner_overrides_inline_and_non_object_8771() {
        let mut inline = json!({"agent_id": OTHER, "k": 1});
        stamp_owner(&mut inline, OWNER);
        assert_eq!(inline, json!({"agent_id": OWNER, "k": 1}));
        let mut scalar = json!("not-an-object");
        stamp_owner(&mut scalar, OWNER);
        assert_eq!(scalar, owner_metadata(OWNER));
    }
}
