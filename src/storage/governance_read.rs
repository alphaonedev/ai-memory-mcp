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
/// #4285 — the RAW `metadata` column of a standard memory (classified
/// Rust-side; the lenient row mapper defaults an unparseable cell to `{}`).
const SQL_SELECT_STANDARD_RAW_METADATA: &str = "SELECT m.metadata FROM memories m WHERE m.id = ?1";
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

/// #4285 — why a bound standard's metadata is corrupt. The `Display` text is a
/// FIXED category (+ line/column when serde reports one): it NEVER carries the
/// stored value, because serde's own error text echoes the offending token
/// (`invalid type: string "..."`) and this text flows to WARN logs, the doctor
/// report and `doctor --json`. The stored `metadata.governance` is out-of-band,
/// caller-influenced data (#4285 F3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptReason {
    /// The whole `metadata` cell is not parseable JSON.
    MetadataNotJson {
        /// serde error category (`io`/`syntax`/`data`/`eof`).
        category: &'static str,
        /// 1-based line, 0 when unknown.
        line: usize,
        /// 1-based column, 0 when unknown.
        column: usize,
    },
    /// The whole `metadata` cell is valid JSON but not an object (array,
    /// string, number, bool, null).
    MetadataNotObject,
    /// `metadata.governance` is present but fails the typed deserialise.
    GovernanceShape {
        /// serde error category.
        category: &'static str,
        /// 1-based line, 0 when unknown.
        line: usize,
        /// 1-based column, 0 when unknown.
        column: usize,
    },
}

fn serde_category(e: &serde_json::Error) -> &'static str {
    use serde_json::error::Category;
    match e.classify() {
        Category::Io => "io",
        Category::Syntax => "syntax",
        Category::Data => "data",
        Category::Eof => "eof",
    }
}

impl CorruptReason {
    /// Value-free reason for a `metadata.governance` typed-deserialise failure.
    #[must_use]
    pub fn from_governance_error(e: &serde_json::Error) -> Self {
        Self::GovernanceShape {
            category: serde_category(e),
            line: e.line(),
            column: e.column(),
        }
    }

    fn from_metadata_error(e: &serde_json::Error) -> Self {
        Self::MetadataNotJson {
            category: serde_category(e),
            line: e.line(),
            column: e.column(),
        }
    }
}

impl std::fmt::Display for CorruptReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MetadataNotJson {
                category,
                line,
                column,
            } => write!(
                f,
                "metadata is not valid JSON ({category} error, line {line}, column {column})"
            ),
            Self::MetadataNotObject => f.write_str("metadata is not a JSON object"),
            Self::GovernanceShape {
                category,
                line,
                column,
            } => write!(
                f,
                "metadata.governance does not deserialize ({category} error, line {line}, \
                 column {column})"
            ),
        }
    }
}

/// #4285 — what a bound standard's metadata contributes to governance. The
/// ONE classification every walker and census shares (sqlite AND postgres), so
/// they cannot disagree on "corrupt".
#[derive(Debug, Clone, PartialEq)]
pub enum StandardMetadata {
    /// Intact metadata with no (or a null) `governance` key: no policy here.
    NoGovernance,
    /// An intact, typed policy together with its raw `governance` blob (the
    /// off-struct knobs such as `require_approval_above_depth` live only there).
    Policy(Box<GovernancePolicy>, serde_json::Value),
    /// Corrupt: a SEVERED level (#2503). It contributes NOTHING — no typed
    /// policy and no raw key — and the walk continues.
    Corrupt(CorruptReason),
}

/// #4285 — classify a parsed `metadata` value. Anything that is not a JSON
/// object, or whose `governance` blob fails the typed deserialise, is
/// `Corrupt`.
#[must_use]
pub fn classify_standard_metadata_value(metadata: &serde_json::Value) -> StandardMetadata {
    if !metadata.is_object() {
        return StandardMetadata::Corrupt(CorruptReason::MetadataNotObject);
    }
    match GovernancePolicy::from_metadata(metadata) {
        None => StandardMetadata::NoGovernance,
        Some(Ok(p)) => {
            let raw = metadata
                .get(crate::META_KEY_GOVERNANCE)
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            StandardMetadata::Policy(Box::new(p), raw)
        }
        Some(Err(e)) => StandardMetadata::Corrupt(CorruptReason::from_governance_error(&e)),
    }
}

/// #4285 — classify the RAW stored `metadata` text of a bound standard. This is
/// the reusable fail-closed classifier (`ns_standard_ancestor` delegates its
/// corrupt / no-policy decision to it, #4356): the lenient row mapper
/// defaults unparseable metadata to `{}`, which reads as "no policy" — fail
/// OPEN — so a governance read must classify the raw column, not the mapped
/// `Memory.metadata`.
#[must_use]
pub fn classify_standard_metadata_text(raw: &str) -> StandardMetadata {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(v) => classify_standard_metadata_value(&v),
        Err(e) => StandardMetadata::Corrupt(CorruptReason::from_metadata_error(&e)),
    }
}

/// #4285 — census projection of [`classify_standard_metadata_value`]: `Some`
/// iff the standard is corrupt.
#[must_use]
pub fn classify_standard_metadata(
    namespace: &str,
    standard_id: &str,
    metadata: &serde_json::Value,
) -> Option<CorruptStandard> {
    corrupt_standard_of(
        namespace,
        standard_id,
        classify_standard_metadata_value(metadata),
    )
}

fn corrupt_standard_of(
    namespace: &str,
    standard_id: &str,
    class: StandardMetadata,
) -> Option<CorruptStandard> {
    match class {
        StandardMetadata::Corrupt(reason) => Some(CorruptStandard {
            namespace: namespace.to_string(),
            standard_id: standard_id.to_string(),
            error: reason.to_string(),
        }),
        StandardMetadata::NoGovernance | StandardMetadata::Policy(..) => None,
    }
}

/// #4285 — read the RAW `metadata` text of a standard memory (`Ok(None)` when
/// the row is gone). A read fault is an `Err` (refuse), never an absence.
pub(super) fn read_raw_standard_metadata(
    conn: &Connection,
    standard_id: &str,
) -> Result<Option<String>> {
    use rusqlite::OptionalExtension;
    let raw: Option<Option<String>> = conn
        .query_row(
            SQL_SELECT_STANDARD_RAW_METADATA,
            params![standard_id],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()
        .context("governance: read standard metadata")?;
    // A NULL metadata cell is "not an object": hand the classifier a non-object.
    Ok(raw.map(|m| m.unwrap_or_else(|| "null".to_string())))
}

/// #4285 — classify the bound standard `standard_id` of `namespace`, WARN-ing on
/// corruption. `Ok(None)` when the memory is gone.
pub(super) fn classify_bound_standard(
    conn: &Connection,
    namespace: &str,
    standard_id: &str,
) -> Result<Option<StandardMetadata>> {
    let Some(raw) = read_raw_standard_metadata(conn, standard_id)? else {
        return Ok(None);
    };
    let class = classify_standard_metadata_text(&raw);
    if let StandardMetadata::Corrupt(reason) = &class {
        warn_corrupt_standard(
            CORRUPT_STANDARD_BACKEND_SQLITE,
            namespace,
            standard_id,
            reason,
        );
    }
    Ok(Some(class))
}

/// #4285 — structured WARN for one corrupt standard met while resolving. The
/// walk continues as a SEVERED level (Owner floor). Shared by both backends.
pub(crate) fn warn_corrupt_standard(
    backend: &str,
    namespace: &str,
    standard_id: &str,
    reason: &CorruptReason,
) {
    tracing::warn!(
        target: TRACE_TARGET_GOVERNANCE_POLICY_READ,
        backend = %backend,
        namespace = %namespace,
        standard_id = %standard_id,
        reason = %reason,
        "stored governance standard is corrupt — treated as a SEVERED \
         standard (#2503): the walk continues and write/promote/delete resolve to at \
         least the Owner floor (#4285). A policy that meant stricter than Owner \
         (approve/consensus) is degraded to Owner until repaired. Re-run \
         `memory_namespace_set_standard` for this namespace to restore the typed shape."
    );
}

/// #4285 — `Some(reason)` iff the standard memory's RAW metadata is corrupt
/// (read surface twin of the enforcement classification). A read fault is an
/// `Err`.
///
/// # Errors
///
/// The metadata read fault.
pub fn standard_metadata_corruption(
    conn: &Connection,
    standard_id: &str,
) -> Result<Option<CorruptReason>> {
    Ok(match read_raw_standard_metadata(conn, standard_id)? {
        Some(raw) => match classify_standard_metadata_text(&raw) {
            StandardMetadata::Corrupt(reason) => Some(reason),
            StandardMetadata::NoGovernance | StandardMetadata::Policy(..) => None,
        },
        None => None,
    })
}

/// #4285 — every namespace (sorted) whose bound standard is corrupt: the
/// doctor Critical and the boot WARN read this.
///
/// # Errors
///
/// A read fault (never reported as "none corrupt").
pub fn list_corrupt_governance_standards(conn: &Connection) -> Result<Vec<CorruptStandard>> {
    // No SQL-side `json_extract` filter: it ERRORS on a metadata cell that is
    // not valid JSON, which is exactly the corruption this census must name.
    // Classification happens Rust-side on the raw text.
    Ok(bound_standard_classes(conn)?
        .into_iter()
        .filter_map(|(ns, id, class)| corrupt_standard_of(&ns, &id, class))
        .collect())
}

/// #4285 — every bound standard (sorted by namespace) with its metadata
/// classification, read from the RAW column. Shared by the census and the
/// capabilities rule summary.
pub(super) fn bound_standard_classes(
    conn: &Connection,
) -> Result<Vec<(String, String, StandardMetadata)>> {
    let mut stmt = conn
        .prepare(
            "SELECT nm.namespace, m.id, m.metadata FROM namespace_meta nm \
             INNER JOIN memories m ON m.id = nm.standard_id \
             ORDER BY nm.namespace ASC",
        )
        .context("governance: prepare bound-standard census")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .context("governance: bound-standard census")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("governance: read bound-standard census")?;
    Ok(rows
        .into_iter()
        .map(|(ns, id, meta)| {
            let class = classify_standard_metadata_text(meta.as_deref().unwrap_or("null"));
            (ns, id, class)
        })
        .collect())
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
