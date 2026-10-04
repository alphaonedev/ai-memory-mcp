// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4492 — the sqlite reader for the bind-time chain-depth refusal. The
//! decision lives once in [`crate::governance::bind_chain_depth`]; this only
//! loads the `namespace_meta` link column (every hop counts, whoever owns it).

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::governance::bind_chain_depth::{
    BIND_CHAIN_OVER_DEPTH, LinkRow, bind_exceeds_chain_depth,
};

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
    let mut stmt = conn
        .prepare(
            "SELECT nm.namespace, nm.parent_namespace FROM namespace_meta nm \
             WHERE nm.parent_namespace IS NOT NULL",
        )
        .context("#4492 bind chain-depth: prepare link graph")?;
    let rows = stmt
        .query_map([], |r| {
            Ok(LinkRow {
                namespace: r.get::<_, String>(0)?,
                parent: r.get::<_, Option<String>>(1)?,
            })
        })
        .context("#4492 bind chain-depth: read link graph")?
        .collect::<rusqlite::Result<Vec<LinkRow>>>()
        .context("#4492 bind chain-depth: read link graph")?;
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
