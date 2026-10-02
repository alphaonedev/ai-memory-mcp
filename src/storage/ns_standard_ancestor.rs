// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4356 — the sqlite reader behind the ancestor-owner bind gate. The verdict
//! lives once in [`crate::ns_standard_ancestor`]; this module only reads the
//! governance chain's levels (nearest-first, the target and `*` excluded).

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

use crate::ns_standard_ancestor::{
    AncestorLevel, GoverningAncestor, SetRefusal, normalise_owner, select_governing_ancestor,
    set_admission,
};

/// Read ONE ancestor level on sqlite. `json_extract(.., '$.governance') IS NOT
/// NULL` is the analogue of the postgres `->` probe (a JSON `null` collapses to
/// SQL NULL), so a bound-but-governance-less standard is `NoPolicy`.
fn read_level(conn: &Connection, namespace: &str) -> Result<AncestorLevel> {
    // ONE statement (a single snapshot): row-present, pointer-set, memory-found,
    // governance-present, owner. `LEFT JOIN` keeps a severed / dangling row
    // visible as `memory_found = 0`.
    type LevelRow = (Option<String>, bool, bool, Option<String>);
    let row: Option<LevelRow> = conn
        .query_row(
            "SELECT nm.standard_id, m.id IS NOT NULL, \
             json_extract(m.metadata, '$.governance') IS NOT NULL, \
             CAST(json_extract(m.metadata, '$.agent_id') AS TEXT) \
             FROM namespace_meta nm LEFT JOIN memories m ON m.id = nm.standard_id \
             WHERE nm.namespace = ?1",
            params![namespace],
            |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, i64>(1)? != 0,
                    r.get::<_, i64>(2)? != 0,
                    r.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()?;
    Ok(match row {
        None => AncestorLevel::Absent,
        Some((None, _, _, _) | (Some(_), false, _, _)) => AncestorLevel::Severed,
        Some((Some(_), true, false, _)) => AncestorLevel::NoPolicy,
        Some((Some(_), true, true, owner)) => AncestorLevel::Governing {
            owner: normalise_owner(owner),
        },
    })
}

/// The nearest governing ancestor of `namespace` on the GOVERNANCE chain.
///
/// # Errors
///
/// Any SQLite error (the caller refuses — fail-closed).
pub fn governing_ancestor_binding(conn: &Connection, namespace: &str) -> Result<GoverningAncestor> {
    let chain = super::build_namespace_governance_chain(conn, namespace);
    select_governing_ancestor(
        chain
            .iter()
            .rev()
            .filter(|n| n.as_str() != namespace && n.as_str() != "*")
            .map(|n| read_level(conn, n)),
    )
}

/// The #3758 rebind gate + the #4356 ancestor gate for a SET on sqlite, from
/// the connection (MCP / HTTP-sqlite / SAL-sqlite funnels). Every read fault
/// maps to [`SetRefusal::Unverifiable`] (fail-closed).
///
/// # Errors
///
/// [`SetRefusal`].
pub fn set_admission_conn(
    conn: &Connection,
    caller: &str,
    bypass: bool,
    namespace: &str,
) -> Result<(), SetRefusal> {
    if bypass {
        return Ok(());
    }
    let binding = super::namespace_standard_binding(conn, namespace).map_err(|e| {
        tracing::error!(target: crate::mcp::error_text::TRACE_TARGET, error = %e,
            "namespace_set_standard: cannot read the current standard binding; refusing");
        SetRefusal::Unverifiable
    })?;
    let ancestor = if crate::ns_standard_ancestor::needs_ancestor(&binding) {
        governing_ancestor_binding(conn, namespace).map_err(|e| {
            tracing::error!(target: crate::mcp::error_text::TRACE_TARGET, error = %e,
                "namespace_set_standard: cannot resolve the governing ancestor; refusing");
            SetRefusal::Unverifiable
        })?
    } else {
        GoverningAncestor::None
    };
    set_admission(caller, false, namespace, &binding, &ancestor)
}
