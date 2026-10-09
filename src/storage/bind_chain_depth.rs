// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4492 — the sqlite reader for the bind-time chain-depth refusal. The
//! decision lives once in [`crate::governance::bind_chain_depth`]; this only
//! loads the `namespace_meta` links the decision needs (every hop counts,
//! whoever owns it).
//!
//! #4718 — the read is the AFFECTED SUBGRAPH, not the whole link column: a
//! bind changes one node's link, and every walk the decision re-measures
//! starts at a root segment and passes through that node, so the rows it can
//! visit are the upward chains from the node's old and new parents plus every
//! row whose own chain reaches the node. One recursive CTE loads exactly those
//! (cycle-safe through `UNION`), so the bind's cost and its write-lock hold
//! follow the neighbourhood, not the fleet-wide namespace count.

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::governance::bind_chain_depth::{
    BIND_CHAIN_OVER_DEPTH, LinkRow, bind_exceeds_chain_depth,
};

/// #4718 — the `namespace_meta` link rows the bind-time decision for binding
/// `namespace` to `new_parent` can visit: the upward chain from `namespace`'s
/// current explicit parent, the upward chain from `new_parent`, and every row
/// whose upward chain reaches `namespace` (the root-segment starts whose walk
/// passes through the bound node). The verdict of
/// [`bind_exceeds_chain_depth`] on these rows is identical to its verdict on
/// the whole link column (pinned by `tests/bind_chain_subgraph_4718.rs`).
///
/// # Errors
///
/// A read fault (the caller refuses the bind, fail closed).
pub fn load_bind_link_subgraph(
    conn: &Connection,
    namespace: &str,
    new_parent: Option<&str>,
) -> Result<Vec<LinkRow>> {
    let mut stmt = conn
        .prepare(
            "WITH RECURSIVE \
               up(ns) AS ( \
                 SELECT ?2 WHERE ?2 IS NOT NULL \
                 UNION \
                 SELECT parent_namespace FROM namespace_meta \
                  WHERE namespace = ?1 AND parent_namespace IS NOT NULL \
                 UNION \
                 SELECT nm.parent_namespace FROM namespace_meta nm JOIN up ON nm.namespace = up.ns \
                  WHERE nm.parent_namespace IS NOT NULL \
               ), \
               down(ns) AS ( \
                 SELECT ?1 \
                 UNION \
                 SELECT nm.namespace FROM namespace_meta nm JOIN down ON nm.parent_namespace = down.ns \
               ) \
             SELECT nm.namespace, nm.parent_namespace FROM namespace_meta nm \
              WHERE nm.parent_namespace IS NOT NULL \
                AND (nm.namespace IN (SELECT ns FROM up) OR nm.namespace IN (SELECT ns FROM down)) \
              ORDER BY nm.namespace",
        )
        .context("#4492 bind chain-depth: prepare link subgraph")?;
    stmt.query_map(rusqlite::params![namespace, new_parent], |r| {
        Ok(LinkRow {
            namespace: r.get::<_, String>(0)?,
            parent: r.get::<_, Option<String>>(1)?,
        })
    })
    .context("#4492 bind chain-depth: read link subgraph")?
    .collect::<rusqlite::Result<Vec<LinkRow>>>()
    .context("#4492 bind chain-depth: read link subgraph")
}

/// Refuse (typed `InvalidArgument`, fixed text) a bind of `namespace` with
/// explicit link `new_parent` when it would push an explicit chain past the
/// bound. Call INSIDE the bind's write transaction, before the row is written.
///
/// # Errors
///
/// The typed refusal, or a read fault (the bind is refused, fail closed).
pub(crate) fn admit_bind(
    conn: &Connection,
    namespace: &str,
    new_parent: Option<&str>,
) -> Result<()> {
    let rows = load_bind_link_subgraph(conn, namespace, new_parent)?;
    if bind_exceeds_chain_depth(&rows, namespace, new_parent) {
        return Err(anyhow::Error::new(super::StorageError::InvalidArgument {
            reason: BIND_CHAIN_OVER_DEPTH.to_string(),
        }));
    }
    Ok(())
}

/// Is `e` the #4492 refusal (for the SAL adapter's typed mapping)?
#[must_use]
pub fn is_bind_chain_over_depth(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<super::StorageError>(),
        Some(super::StorageError::InvalidArgument { reason }) if reason == BIND_CHAIN_OVER_DEPTH
    )
}
