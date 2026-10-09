// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4356 — the sqlite reader behind the ancestor-owner bind gate. The verdict
//! lives once in [`crate::ns_standard_ancestor`]; this module only reads the
//! governance chain's levels (nearest-first, the target and `*` excluded).
//!
//! Every read here is FALLIBLE (a fault refuses the bind, vote amendment d):
//! the chain is the shared [`super::build_namespace_governance_chain`], which
//! (since #4043) propagates every parent / owner read fault as an `Err` instead
//! of swallowing it into "no parent" — a dropped explicit ancestor would be
//! fail-open for this gate. #4356 originally carried a separate strict twin;
//! it is gone so the two builders cannot drift.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::ns_standard_ancestor::{
    AncestorLevel, DescendantLevel, GoverningAncestor, SetRefusal, classify_standard_metadata_text,
    descendant_admission, select_governing_ancestor, select_governing_descendant, set_admission,
};

/// The RAW level row: `namespace_meta.standard_id` and the bound memory's RAW
/// `metadata` text. `LEFT JOIN` keeps a severed / dangling row visible.
const SQL_LEVEL: &str = "SELECT nm.standard_id, m.id IS NOT NULL, m.metadata \
     FROM namespace_meta nm LEFT JOIN memories m ON m.id = nm.standard_id \
     WHERE nm.namespace = ?1";

/// Read ONE ancestor level on sqlite in one statement (one snapshot). The
/// stored metadata is classified Rust-side from the RAW column by the shared
/// [`classify_standard_metadata_text`] (#4356 CR1): `json_extract` would read a
/// JSON array / string metadata cell as "no governance" (NoPolicy, skipped)
/// and the lenient row mapper reads unparseable text as `{}` — both fail open.
fn read_level(conn: &Connection, namespace: &str) -> Result<AncestorLevel> {
    type LevelRow = (Option<String>, bool, Option<String>);
    let row: Option<LevelRow> = conn
        .query_row(SQL_LEVEL, params![namespace], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, i64>(1)? != 0,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .optional()
        .context("#4356 ancestor level read")?;
    Ok(match row {
        None => AncestorLevel::Absent,
        Some((None, _, _) | (Some(_), false, _)) => AncestorLevel::Severed,
        // A NULL metadata cell is not an object: corrupt.
        Some((Some(_), true, raw)) => {
            classify_standard_metadata_text(raw.as_deref().unwrap_or("null"))
        }
    })
}

/// The nearest governing ancestor of `namespace` on the GOVERNANCE chain.
///
/// # Errors
///
/// Any SQLite error (the caller refuses — fail-closed).
pub fn governing_ancestor_binding(conn: &Connection, namespace: &str) -> Result<GoverningAncestor> {
    let chain = super::build_namespace_governance_chain(conn, namespace)?;
    select_governing_ancestor(
        chain
            .iter()
            .rev()
            .filter(|n| n.as_str() != namespace && n.as_str() != "*")
            .map(|n| read_level(conn, n)),
    )
}

/// #4713 — the RAW descendant rows: every `namespace_meta` row strictly below
/// `?1` (the `LIKE` pattern `<escaped target>/%`), `LEFT JOIN`ed so a severed
/// / dangling binding stays visible.
const SQL_DESCENDANT_LEVELS: &str = "SELECT nm.standard_id, m.id IS NOT NULL, m.metadata \
     FROM namespace_meta nm LEFT JOIN memories m ON m.id = nm.standard_id \
     WHERE nm.namespace LIKE ?1 ESCAPE '\\' ORDER BY nm.namespace";

/// The `LIKE` pattern matching every namespace strictly below `namespace`,
/// with the pattern metacharacters of the target escaped so a `_` or `%` in
/// a namespace matches literally.
fn descendants_like_pattern(namespace: &str) -> String {
    let mut pattern = String::with_capacity(namespace.len() + 2);
    for c in namespace.chars() {
        if matches!(c, '\\' | '%' | '_') {
            pattern.push('\\');
        }
        pattern.push(c);
    }
    pattern.push_str("/%");
    pattern
}

/// #4713 — the descendant-side verdict for a bind at `namespace` by
/// `caller`: every standard bound strictly below the target, classified
/// Rust-side from the RAW column exactly as [`read_level`] classifies an
/// ancestor (a NULL pointer, a reaped memory and a corrupt blob are all
/// Severed).
///
/// # Errors
///
/// Any SQLite error (the caller refuses — fail-closed).
pub fn governing_descendants_binding(
    conn: &Connection,
    namespace: &str,
    caller: &str,
) -> Result<DescendantLevel> {
    type LevelRow = (Option<String>, bool, Option<String>);
    let mut stmt = conn
        .prepare(SQL_DESCENDANT_LEVELS)
        .context("#4713 descendant levels prepare")?;
    let rows = stmt
        .query_map(params![descendants_like_pattern(namespace)], |r| {
            Ok::<LevelRow, rusqlite::Error>((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, i64>(1)? != 0,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .context("#4713 descendant levels read")?;
    let levels = rows.map(|row| {
        row.context("#4713 descendant level row")
            .map(|row| match row {
                (None, _, _) | (Some(_), false, _) => AncestorLevel::Severed,
                (Some(_), true, raw) => {
                    classify_standard_metadata_text(raw.as_deref().unwrap_or("null"))
                }
            })
    });
    select_governing_descendant(caller, levels)
}

/// The #3758 rebind gate + the #4356 ancestor gate + the #4713 descendant
/// gate for a SET on sqlite, from the connection (MCP / HTTP-sqlite /
/// SAL-sqlite funnels). Every read fault maps to
/// [`SetRefusal::Unverifiable`] (fail-closed). Callers that write run it
/// INSIDE their `BEGIN IMMEDIATE` transaction (race-safe re-check).
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
    let needs_chain = crate::ns_standard_ancestor::needs_ancestor(&binding);
    let ancestor = if needs_chain {
        governing_ancestor_binding(conn, namespace).map_err(|e| {
            tracing::error!(target: crate::mcp::error_text::TRACE_TARGET, error = %e,
                "namespace_set_standard: cannot resolve the governing ancestor; refusing");
            SetRefusal::Unverifiable
        })?
    } else {
        GoverningAncestor::None
    };
    set_admission(caller, false, namespace, &binding, &ancestor)?;
    if !needs_chain {
        return Ok(());
    }
    // #4713 — the descendant-side twin, for exactly the binds that consulted
    // the ancestor.
    let descendants = governing_descendants_binding(conn, namespace, caller).map_err(|e| {
        tracing::error!(target: crate::mcp::error_text::TRACE_TARGET, error = %e,
            "namespace_set_standard: cannot resolve the governed descendants; refusing");
        SetRefusal::Unverifiable
    })?;
    descendant_admission(&binding, &descendants).inspect_err(|_| {
        tracing::warn!(
            target: crate::handlers::AUTHZ_TRACE_TARGET,
            "namespace-standard descendant refusal: first bind or unowned rebind on {namespace}: a standard bound below it is governed by another principal or unresolvable (#4713)"
        );
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("open")
    }

    fn standard(conn: &Connection, ns: &str, metadata: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
             confidence, source, access_count, created_at, updated_at, metadata) \
             VALUES (?1, 'long', ?2, ?3, 'std', '[]', 5, 1.0, 'test', 0, ?4, ?4, ?5)",
            params![id, ns, format!("std {id}"), now, metadata],
        )
        .expect("insert standard");
        id
    }

    fn meta(conn: &Connection, ns: &str, sid: Option<&str>, parent: Option<&str>) {
        conn.execute(
            "INSERT INTO namespace_meta (namespace, standard_id, updated_at, parent_namespace) \
             VALUES (?1, ?2, '2026-10-01T00:00:00Z', ?3)",
            params![ns, sid, parent],
        )
        .expect("insert namespace_meta");
    }

    /// #4356 CR1 at the reader: an ancestor whose stored metadata is a JSON
    /// array / string / invalid text / a corrupt governance blob is SEVERED,
    /// so a stranger's first bind below it is refused (never NoPolicy-skipped).
    #[test]
    fn corrupt_ancestor_metadata_reads_severed_and_refuses_4356() {
        for raw in [
            "[]",
            r#""x""#,
            "{not json",
            r#"{"agent_id":"a","governance":{"write":42}}"#,
        ] {
            let c = conn();
            let sid = standard(&c, "s", raw);
            meta(&c, "gov", Some(&sid), None);
            assert_eq!(
                governing_ancestor_binding(&c, "gov/leaf").expect("read"),
                GoverningAncestor::Severed,
                "{raw}"
            );
            assert_eq!(
                set_admission_conn(&c, "s", false, "gov/leaf"),
                Err(SetRefusal::AncestorUnresolvable),
                "{raw}"
            );
        }
    }

    /// #4713 — B binds `root/proj` (a governed standard B owns). X's FIRST
    /// bind at the unbound root segment `root` is refused on sqlite; B may
    /// bind `root`; the operator bypass may; a sibling that merely shares a
    /// string prefix is not a descendant; a `_` in the target is matched
    /// literally (LIKE escaping).
    #[test]
    fn first_bind_above_a_foreign_owned_descendant_is_refused_4713() {
        let c = conn();
        let b_std = standard(
            &c,
            "s",
            r#"{"agent_id":"b","governance":{"write":"owner"}}"#,
        );
        meta(&c, "root/proj", Some(&b_std), None);
        assert_eq!(
            governing_descendants_binding(&c, "root", "x").expect("read"),
            DescendantLevel::ForeignOwned
        );
        assert_eq!(
            governing_descendants_binding(&c, "root", "b").expect("read"),
            DescendantLevel::Ungoverned
        );
        assert_eq!(
            set_admission_conn(&c, "x", false, "root"),
            Err(SetRefusal::NotOwner)
        );
        assert!(set_admission_conn(&c, "b", false, "root").is_ok());
        assert!(set_admission_conn(&c, "x", true, "root").is_ok());
        // Not descendants: a string-prefix sibling, and the row itself.
        assert!(set_admission_conn(&c, "x", false, "roo").is_ok());
        assert!(set_admission_conn(&c, "x", false, "root2").is_ok());
        // LIKE escaping: `team_x/%` must not match `teamyx/p`.
        meta(&c, "teamyx/p", Some(&b_std), None);
        assert!(set_admission_conn(&c, "x", false, "team_x").is_ok());
        assert_eq!(
            set_admission_conn(&c, "x", false, "teamyx"),
            Err(SetRefusal::NotOwner)
        );
    }

    /// #4713 — descendants that do not GOVERN never block: an unowned
    /// standard, a standard with no policy. A severed / dangling descendant
    /// fails closed with its own reason.
    #[test]
    fn descendant_gate_unowned_passes_and_severed_fails_closed_4713() {
        let c = conn();
        let unowned = standard(&c, "s", r#"{"governance":{"write":"any"}}"#);
        meta(&c, "open/a", Some(&unowned), None);
        let no_policy = standard(&c, "s", r#"{"agent_id":"b"}"#);
        meta(&c, "open/b", Some(&no_policy), None);
        assert_eq!(
            governing_descendants_binding(&c, "open", "x").expect("read"),
            DescendantLevel::Ungoverned
        );
        assert!(set_admission_conn(&c, "x", false, "open").is_ok());

        // Severed (NULL pointer) and dangling (reaped memory) descendants.
        meta(&c, "sev/null", None, None);
        assert_eq!(
            set_admission_conn(&c, "x", false, "sev"),
            Err(SetRefusal::DescendantUnresolvable)
        );
        let d = conn();
        meta(&d, "dang/gone", Some("no-such-memory"), None);
        assert_eq!(
            set_admission_conn(&d, "x", false, "dang"),
            Err(SetRefusal::DescendantUnresolvable)
        );
        // A corrupt descendant standard is severed too (#4356 CR1 parity).
        let e = conn();
        let corrupt = standard(&e, "s", "[]");
        meta(&e, "bad/child", Some(&corrupt), None);
        assert_eq!(
            set_admission_conn(&e, "x", false, "bad"),
            Err(SetRefusal::DescendantUnresolvable)
        );
    }

    /// A read fault on the chain refuses (Unverifiable), never "ungoverned".
    #[test]
    fn chain_read_fault_refuses_4356() {
        let c = conn();
        c.execute_batch("DROP TABLE namespace_meta; CREATE TABLE namespace_meta (namespace TEXT)")
            .expect("break the table");
        assert_eq!(
            set_admission_conn(&c, "s", false, "gov/leaf"),
            Err(SetRefusal::Unverifiable)
        );
    }

    /// F1 (code review, mutation-proven): the chain BUILDER must propagate a
    /// read fault, not swallow it into "no parent". One hop's `parent_namespace`
    /// is a BLOB (fails the String read on that hop only; every level read stays
    /// intact), so a builder that swallowed the fault would drop the governed
    /// `top` ancestor and ADMIT a stranger. The shared builder returns `Err` and
    /// the gate refuses. Red if the shared builder swallows a read fault.
    #[test]
    fn chain_builder_propagates_a_parent_read_fault_4356() {
        let c = conn();
        let a = standard(
            &c,
            "s",
            r#"{"agent_id":"a","governance":{"write":"owner"}}"#,
        );
        let n = standard(&c, "s", r#"{"agent_id":"a"}"#);
        meta(&c, "top", Some(&a), None);
        meta(&c, "root", Some(&n), Some("top"));
        // Sanity (intact): the chain reaches `top`, the stranger is refused.
        assert!(
            crate::storage::build_namespace_governance_chain(&c, "root/leaf")
                .expect("intact chain")
                .contains(&"top".to_string())
        );
        assert_eq!(
            set_admission_conn(&c, "stranger", false, "root/leaf"),
            Err(SetRefusal::NotOwner)
        );
        c.execute(
            "UPDATE namespace_meta SET parent_namespace = x'00ff' WHERE namespace = 'root'",
            [],
        )
        .expect("blob the parent link");
        assert!(
            crate::storage::build_namespace_governance_chain(&c, "root/leaf").is_err(),
            "the shared builder must propagate the read fault, not drop `top`"
        );
        assert_eq!(
            set_admission_conn(&c, "stranger", false, "root/leaf"),
            Err(SetRefusal::Unverifiable),
            "a chain read fault refuses, never admits"
        );
    }
}
