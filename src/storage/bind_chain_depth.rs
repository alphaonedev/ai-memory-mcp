// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4492 — the sqlite reader for the bind-time chain-depth refusal. The
//! decision lives once in [`crate::governance::bind_chain_depth`]; this only
//! loads the `namespace_meta` link graph (owners normalised exactly as the
//! sqlite chain builder's `namespace_standard_owner` does: `metadata.agent_id`
//! as a string through the lenient row mapping, empty / `system` = unowned).

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::governance::bind_chain_depth::{
    BIND_CHAIN_OVER_DEPTH, LinkRow, bind_exceeds_chain_depth,
};

fn owner_from_metadata(raw: Option<&str>) -> Option<String> {
    let v: serde_json::Value = raw
        .and_then(|r| serde_json::from_str(r).ok())
        .unwrap_or(serde_json::Value::Null);
    crate::ns_standard_ancestor::normalise_owner(
        v.get(crate::META_KEY_AGENT_ID)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
    )
}

/// Refuse (typed `InvalidArgument`, fixed text) a bind of `namespace` to a
/// standard owned by `new_owner` with explicit link `new_parent` when it would
/// push an entitled chain past the bound. Call INSIDE the bind's write
/// transaction, before the row is written.
///
/// # Errors
///
/// The typed refusal, or a read fault (the bind is refused, fail closed).
pub(crate) fn admit_bind(
    conn: &Connection,
    namespace: &str,
    new_parent: Option<&str>,
    new_owner: Option<&str>,
) -> Result<()> {
    let mut stmt = conn
        .prepare(
            "SELECT nm.namespace, nm.parent_namespace, m.metadata FROM namespace_meta nm \
             LEFT JOIN memories m ON m.id = nm.standard_id",
        )
        .context("#4492 bind chain-depth: prepare link graph")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .context("#4492 bind chain-depth: read link graph")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("#4492 bind chain-depth: read link graph")?;
    let links: Vec<LinkRow> = rows
        .into_iter()
        .map(|(namespace, parent, meta)| LinkRow {
            namespace,
            parent,
            owner: owner_from_metadata(meta.as_deref()),
        })
        .collect();
    let owner = crate::ns_standard_ancestor::normalise_owner(new_owner.map(str::to_string));
    if bind_exceeds_chain_depth(&links, namespace, new_parent, owner.as_deref()) {
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
