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

// ---------------------------------------------------------------------------
// #4285 (5-agent vote 4d3ea1c5, memory 1c3e2889; reverses #1384) — a governance
// standard whose `metadata.governance` does not deserialize is a SEVERED level
// (#2503), never `NoPolicy` and never a hard refusal.
// ---------------------------------------------------------------------------

/// Backend label for the sqlite corrupt-standard WARN / doctor section.
pub const CORRUPT_STANDARD_BACKEND_SQLITE: &str = "sqlite";
/// Backend label for the postgres corrupt-standard WARN / doctor section.
pub const CORRUPT_STANDARD_BACKEND_POSTGRES: &str = "postgres";

/// #4285 — one namespace whose bound standard carries a `metadata.governance`
/// blob that fails the typed deserialise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorruptStandard {
    /// The namespace the standard is bound to.
    pub namespace: String,
    /// The standard memory id.
    pub standard_id: String,
    /// The typed-deserialise error.
    pub error: String,
}

/// #4285 — the ONE classifier of a standard's metadata: `Some` iff
/// `metadata.governance` is present and does not deserialize. Shared by the
/// sqlite and postgres census so the two cannot disagree on "corrupt".
#[must_use]
pub fn classify_standard_metadata(
    namespace: &str,
    standard_id: &str,
    metadata: &serde_json::Value,
) -> Option<CorruptStandard> {
    match GovernancePolicy::from_metadata(metadata) {
        Some(Err(e)) => Some(CorruptStandard {
            namespace: namespace.to_string(),
            standard_id: standard_id.to_string(),
            error: e.to_string(),
        }),
        Some(Ok(_)) | None => None,
    }
}

/// #4285 — structured WARN for one corrupt standard met while resolving. The
/// walk continues as a SEVERED level (Owner floor). Shared by both backends.
pub(crate) fn warn_corrupt_standard(
    backend: &str,
    namespace: &str,
    standard_id: &str,
    error: &dyn std::fmt::Display,
) {
    tracing::warn!(
        target: TRACE_TARGET_GOVERNANCE_POLICY_READ,
        backend = %backend,
        namespace = %namespace,
        standard_id = %standard_id,
        error = %error,
        "stored metadata.governance failed typed deserialise — treated as a SEVERED \
         standard (#2503): the walk continues and write/promote/delete resolve to at \
         least the Owner floor (#4285). A policy that meant stricter than Owner \
         (approve/consensus) is degraded to Owner until repaired. Re-run \
         `memory_namespace_set_standard` for this namespace to restore the typed shape."
    );
}

/// #4285 — a resolved standard memory's contribution to the chain walk.
pub(super) fn level_from_standard(
    namespace: &str,
    standard_id: &str,
    mem: &super::Memory,
) -> super::NamespaceLevel {
    match GovernancePolicy::from_metadata(&mem.metadata) {
        Some(Ok(p)) => super::NamespaceLevel::Policy(Box::new(p)),
        Some(Err(e)) => {
            warn_corrupt_standard(CORRUPT_STANDARD_BACKEND_SQLITE, namespace, standard_id, &e);
            super::NamespaceLevel::Severed
        }
        None => super::NamespaceLevel::NoPolicy,
    }
}

/// #4285 — every namespace (sorted) whose bound standard is corrupt: the
/// doctor Critical and the boot WARN read this.
///
/// # Errors
///
/// A read fault (never reported as "none corrupt").
pub fn list_corrupt_governance_standards(conn: &Connection) -> Result<Vec<CorruptStandard>> {
    let mut stmt = conn
        .prepare(
            "SELECT nm.namespace, m.id, m.metadata FROM namespace_meta nm \
             INNER JOIN memories m ON m.id = nm.standard_id \
             WHERE json_extract(m.metadata, '$.governance') IS NOT NULL \
             ORDER BY nm.namespace ASC",
        )
        .context("governance: prepare corrupt-standard census")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .context("governance: corrupt-standard census")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("governance: read corrupt-standard census")?;
    let mut out = Vec::new();
    for (ns, id, meta) in rows {
        match serde_json::from_str::<serde_json::Value>(&meta) {
            Ok(v) => out.extend(classify_standard_metadata(&ns, &id, &v)),
            Err(e) => out.push(CorruptStandard {
                namespace: ns,
                standard_id: id,
                error: format!("metadata is not valid JSON: {e}"),
            }),
        }
    }
    Ok(out)
}

/// #4285 — boot WARN naming EVERY corrupt standard (one summary line; silent
/// when none). Best-effort by contract: the census never gates boot.
pub fn warn_corrupt_governance_standards(backend: &str, corrupt: &[CorruptStandard]) {
    if corrupt.is_empty() {
        return;
    }
    let listing = corrupt
        .iter()
        .map(|c| format!("{} (standard {}: {})", c.namespace, c.standard_id, c.error))
        .collect::<Vec<_>>()
        .join("; ");
    tracing::warn!(
        target: TRACE_TARGET_GOVERNANCE_POLICY_READ,
        backend = %backend,
        count = corrupt.len(),
        namespaces = %listing,
        "{} namespace governance standard(s) are CORRUPT (metadata.governance does not \
         deserialize) and resolve as SEVERED (Owner floor, #4285) — repair each with \
         `memory_namespace_set_standard`; `ai-memory doctor` reports this as Critical",
        corrupt.len()
    );
}

/// #4285 — the sqlite boot hook (serve + MCP stdio): census then WARN.
/// Best-effort — a census fault is itself a WARN, never a boot failure.
pub fn boot_warn_corrupt_governance_standards(conn: &Connection) {
    match list_corrupt_governance_standards(conn) {
        Ok(c) => warn_corrupt_governance_standards(CORRUPT_STANDARD_BACKEND_SQLITE, &c),
        Err(e) => tracing::warn!(
            target: TRACE_TARGET_GOVERNANCE_POLICY_READ,
            error = %e,
            "corrupt governance standard census could not be read at boot (#4285)"
        ),
    }
}
