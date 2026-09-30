// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4043 — FALLIBLE governance-policy reads. Every governance walker reads
//! through these, so a read fault is an `Err` (refuse), never an absence
//! ("unconfigured" = allow-on-silence). Split out of `storage/mod.rs`
//! (QUAL-10: no ceiling bump).

use anyhow::{Context, Result};
use rusqlite::{Connection, params};

use crate::models::GovernancePolicy;

/// #4043 — the one `namespace_meta.standard_id` probe the storage layer issues.
pub(crate) const SQL_SELECT_NAMESPACE_STANDARD_ID: &str =
    "SELECT standard_id FROM namespace_meta WHERE namespace = ?1";
/// Tracing target for governance-policy read drift / faults (#1384, #4043).
pub(crate) const TRACE_TARGET_GOVERNANCE_POLICY_READ: &str = "ai_memory::governance::policy_read";
/// #4043 — context attached when a governance policy / threshold cannot be
/// read and the governed action is refused.
pub const GOVERNANCE_POLICY_UNREADABLE: &str = "governance policy unreadable (#4043 fail-CLOSED)";
/// #4043 — context for a failed read of a bound namespace standard.
pub(super) const CTX_READ_NAMESPACE_STANDARD: &str = "governance: read namespace standard";

/// #4043 — FALLIBLE twin of [`get_namespace_standard`] for the GOVERNANCE
/// walkers. `Ok(None)` means "no row, or a row whose `standard_id` is NULL";
/// every other rusqlite failure is an `Err`, never an absence. The lenient
/// [`get_namespace_standard`] collapses a read fault into "no standard bound",
/// which is correct for display but FAILS OPEN when a governance walker reads
/// it (an unreadable policy looks unconfigured).
pub(super) fn try_get_namespace_standard(
    conn: &Connection,
    namespace: &str,
) -> Result<Option<String>> {
    use rusqlite::OptionalExtension;
    let row: Option<Option<String>> = conn
        .query_row(SQL_SELECT_NAMESPACE_STANDARD_ID, params![namespace], |r| {
            r.get::<_, Option<String>>(0)
        })
        .optional()
        .context("governance: read namespace_meta.standard_id")?;
    Ok(row.flatten())
}

/// #4043 — FALLIBLE twin of [`get_namespace_parent`] for the GOVERNANCE chain:
/// a read fault is an `Err`, never "no parent" (dropping an entitled parent
/// drops its policy layer — fail-open).
pub(super) fn try_get_namespace_parent(
    conn: &Connection,
    namespace: &str,
) -> Result<Option<String>> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT parent_namespace FROM namespace_meta WHERE namespace = ?1 AND parent_namespace IS NOT NULL",
        params![namespace],
        |r| r.get(0),
    )
    .optional()
    .context("governance: read namespace_meta.parent_namespace")
}

/// #4043 — resolve the namespace policy for a NON-AUTHORIZATION convenience
/// knob (auto-classify, auto-atomise mode, the atomise-candidate report): a
/// read fault logs a WARN and yields [`GovernancePolicy::default`], whose
/// knobs are all OFF, so the degradation is "the optional feature does not
/// run", never a wider permission.
///
/// NEVER use this for an authorization decision, a depth cap, an approver
/// type or any gate: those call [`resolve_governance_policy`] and refuse on
/// `Err`.
#[must_use]
pub fn resolve_governance_policy_for_optional_feature(
    conn: &Connection,
    namespace: &str,
) -> GovernancePolicy {
    match super::resolve_governance_policy(conn, namespace) {
        Ok(policy) => policy.unwrap_or_default(),
        Err(e) => {
            tracing::warn!(
                target: TRACE_TARGET_GOVERNANCE_POLICY_READ,
                namespace = %namespace,
                error = %e,
                "governance policy unreadable; optional policy-driven feature stays OFF (#4043)"
            );
            GovernancePolicy::default()
        }
    }
}

/// The LOOKUP chain's defensive fallback: that view reads parent links
/// leniently and consults no owner, so it cannot fail today.
pub(super) fn structural_chain_fallback(namespace: &str, e: &anyhow::Error) -> Vec<String> {
    tracing::warn!(
        target: TRACE_TARGET_GOVERNANCE_POLICY_READ,
        namespace = %namespace,
        error = %e,
        "lookup namespace chain read failed; returning the structural chain"
    );
    let mut chain = vec!["*".to_string()];
    if namespace != "*" {
        chain.extend(
            crate::models::namespace_ancestors(namespace)
                .into_iter()
                .rev(),
        );
    }
    chain
}

/// #4043 — the gate's disposition for an UNREADABLE policy. It is not an
/// ungoverned one: under `Enforce` the fault propagates as an `Err` (every
/// caller refuses the write); `Advisory` never blocks by contract, so it logs
/// and allows — exactly what it would do with the policy in hand.
///
/// # Errors
///
/// The read fault, with context, under every mode but `Advisory`.
pub(super) fn unreadable_policy_decision(
    mode: crate::config::PermissionsMode,
    action: crate::models::GovernedAction,
    namespace: &str,
    agent_id: &str,
    e: anyhow::Error,
) -> Result<crate::models::GovernanceDecision> {
    if mode == crate::config::PermissionsMode::Advisory {
        tracing::warn!(
            target: crate::governance::GOVERNANCE_GATE_TRACE_TARGET,
            namespace = %namespace,
            agent_id = %agent_id,
            action = ?action,
            error = %e,
            "permissions.mode=advisory: governance policy UNREADABLE — would refuse under enforce"
        );
        return Ok(crate::models::GovernanceDecision::Allow);
    }
    Err(e.context(format!(
        "governance policy for namespace '{namespace}' could not be read; refusing (#4043)"
    )))
}
