// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4356 — the sqlite reader behind the ancestor-owner bind gate. The verdict
//! lives once in [`crate::ns_standard_ancestor`]; this module only reads the
//! governance chain's levels (nearest-first, the target and `*` excluded).
//!
//! Every read here is FALLIBLE (a fault refuses the bind, vote amendment d):
//! the chain is built by [`governance_chain_strict`], the fault-propagating
//! twin of the lenient `build_namespace_governance_chain` (which swallows a
//! parent / owner read fault into "no parent" and would drop an explicit
//! ancestor, fail-open for this gate). The twin calls the same canonical
//! helpers on the no-fault path and is pinned equal to the lenient builder by
//! `strict_chain_matches_the_governance_chain_4356`.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::ns_standard_ancestor::{
    AncestorLevel, GoverningAncestor, SetRefusal, classify_standard_metadata_text,
    select_governing_ancestor, set_admission,
};

/// Explicit-parent hop cap; the SAME bound as the lenient builder
/// (`build_namespace_chain_view`'s `MAX_EXPLICIT_DEPTH`).
const MAX_EXPLICIT_DEPTH: usize = 8;

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

/// Fallible `namespace_meta.parent_namespace` read (twin of the lenient
/// `get_namespace_parent`, same SQL).
fn parent_strict(conn: &Connection, namespace: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT parent_namespace FROM namespace_meta WHERE namespace = ?1 AND parent_namespace IS NOT NULL",
        params![namespace],
        |r| r.get(0),
    )
    .optional()
    .context("#4356 ancestor chain: parent_namespace read")
}

/// Fallible twin of the lenient `namespace_standard_owner` (#2542 entitlement
/// owner): the same `standard_id` probe, the same `db::get` row mapping and
/// the same unowned set, but a read fault propagates.
fn standard_owner_strict(conn: &Connection, namespace: &str) -> Result<Option<String>> {
    let sid: Option<Option<String>> = conn
        .query_row(
            "SELECT nm.standard_id FROM namespace_meta nm WHERE nm.namespace = ?1",
            params![namespace],
            |r| r.get(0),
        )
        .optional()
        .context("#4356 ancestor chain: standard_id read")?;
    let Some(sid) = sid.flatten() else {
        return Ok(None);
    };
    let owner = super::get(conn, &sid)?.and_then(|mem| {
        mem.metadata
            .get(crate::mcp::param_names::AGENT_ID)
            .and_then(|v| v.as_str())
            .map(str::to_string)
    });
    Ok(crate::ns_standard_ancestor::normalise_owner(owner))
}

/// The GOVERNANCE chain of `namespace` (top-down, `*` first), built exactly
/// as the lenient `build_namespace_governance_chain` builds it — `/`-derived
/// ancestors plus the ENTITLED explicit parents above the rootmost one
/// (#2542 per-hop rule) — except that every read fault is an `Err`.
///
/// # Errors
///
/// Any SQLite read fault.
pub(crate) fn governance_chain_strict(conn: &Connection, namespace: &str) -> Result<Vec<String>> {
    let mut chain = vec!["*".to_string()];
    if namespace == "*" {
        return Ok(chain);
    }
    let hierarchy: Vec<String> = crate::models::namespace_ancestors(namespace)
        .into_iter()
        .rev()
        .collect();
    if let Some(root) = hierarchy.first().cloned() {
        let mut explicit_above: Vec<String> = Vec::new();
        let mut current = root;
        for _ in 0..MAX_EXPLICIT_DEPTH {
            let Some(p) = parent_strict(conn, &current)? else {
                break;
            };
            if p == "*" || explicit_above.contains(&p) || hierarchy.contains(&p) {
                break;
            }
            let entitled = match standard_owner_strict(conn, &p)? {
                None => true,
                Some(parent_owner) => {
                    standard_owner_strict(conn, &current)?.as_deref() == Some(parent_owner.as_str())
                }
            };
            if !entitled {
                break;
            }
            explicit_above.push(p.clone());
            current = p;
        }
        chain.extend(explicit_above.into_iter().rev());
    }
    for entry in hierarchy {
        if !chain.contains(&entry) {
            chain.push(entry);
        }
    }
    Ok(chain)
}

/// The nearest governing ancestor of `namespace` on the GOVERNANCE chain.
///
/// # Errors
///
/// Any SQLite error (the caller refuses — fail-closed).
pub fn governing_ancestor_binding(conn: &Connection, namespace: &str) -> Result<GoverningAncestor> {
    let chain = governance_chain_strict(conn, namespace)?;
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
/// maps to [`SetRefusal::Unverifiable`] (fail-closed). Callers that write run
/// it INSIDE their `BEGIN IMMEDIATE` transaction (race-safe re-check).
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

    /// The strict twin is the lenient governance builder on every no-fault
    /// fixture: no row, an entitled explicit parent, an UNENTITLED
    /// (cross-tenant, dropped) parent, an unowned parent and a cycle.
    #[test]
    fn strict_chain_matches_the_governance_chain_4356() {
        let c = conn();
        let a = standard(&c, "s", r#"{"agent_id":"a"}"#);
        let b = standard(&c, "s", r#"{"agent_id":"b"}"#);
        let u = standard(&c, "s", r#"{"agent_id":"system"}"#);
        meta(&c, "top", Some(&a), None);
        meta(&c, "same", Some(&a), Some("top"));
        meta(&c, "cross", Some(&b), Some("top"));
        meta(&c, "free", Some(&u), None);
        meta(&c, "tofree", Some(&b), Some("free"));
        meta(&c, "cyc1", Some(&a), Some("cyc2"));
        meta(&c, "cyc2", Some(&a), Some("cyc1"));
        for ns in [
            "none/x/y", "same", "same/x", "cross/x", "tofree/x", "cyc1/x", "*", "top",
        ] {
            assert_eq!(
                governance_chain_strict(&c, ns).expect("strict"),
                crate::storage::build_namespace_governance_chain(&c, ns),
                "{ns}"
            );
        }
        assert!(
            !governance_chain_strict(&c, "cross/x")
                .expect("strict")
                .contains(&"top".to_string()),
            "a cross-tenant explicit parent is not on the governance chain"
        );
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
}
