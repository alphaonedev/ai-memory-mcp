// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4477 — the ONE postgres namespace-chain builder, for the pool and the
//! transaction twins alike (both pass a connection). It replaces the two
//! copies that kept only the 5 most-specific `/` levels and 5 explicit hops
//! (`GOVERNANCE_INHERITANCE_DEPTH_CAP`, F-A2A1.2): the chain is now COMPLETE,
//! bounded by `crate::governance::chain_depth` with a fail-closed refusal,
//! exactly as the sqlite builder (`storage::build_namespace_chain_view`). Own
//! module for the qual_10 budget of `postgres.rs`.

use super::{StoreResult, pg_warn_governance_graft_excluded, to_store_err};
use crate::governance::chain_depth::{admit_explicit_parent, slash_chain};
use crate::store::StoreError;

/// The concrete owner (`metadata.agent_id`) of `namespace`'s bound standard,
/// or `None` (no standard, severed / dangling pointer, or unowned: empty /
/// `system`). Postgres twin of `storage::namespace_standard_owner`.
async fn standard_owner(
    conn: &mut sqlx::PgConnection,
    namespace: &str,
) -> StoreResult<Option<String>> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT m.metadata->>'agent_id' FROM namespace_meta nm \
         JOIN memories m ON m.id = nm.standard_id WHERE nm.namespace = $1",
    )
    .bind(namespace)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| to_store_err("namespace chain standard owner", e))?;
    Ok(row
        .and_then(|(o,)| o)
        .filter(|o| !o.is_empty() && o != crate::identity::sentinels::SYSTEM_PRINCIPAL))
}

/// Map the depth refusal to the store error (fixed, value-free text). A
/// governance chain that cannot be resolved completely is the same class as
/// an unreadable policy on sqlite (#4043: the governed operation is refused
/// with a 500), so it is a backend error here too, never a 400 that reads as
/// "the caller's input was wrong".
fn over_depth(e: crate::governance::chain_depth::ChainOverDepth) -> StoreError {
    StoreError::Backend(crate::store::BoxBackendError::new(e.reason()))
}

/// Build the namespace chain TOP-DOWN (`*`, explicit parents above the
/// rootmost `/` segment, then the `/` hierarchy) on `conn`.
///
/// `governance` selects the view (mirrors the sqlite `ChainView`): `false`
/// follows every `parent_namespace` link (LOOKUP); `true` follows a link only
/// when ENTITLED (#2542: the parent is unowned, or owned by the declaring
/// namespace's owner) and stops at the first unentitled one.
///
/// # Errors
///
/// A storage fault, or a backend error (`StoreError::Backend`, HTTP 500, the
/// #4043 unreadable-policy class) with the #4477 refusal when a walk would
/// exceed `MAX_NAMESPACE_DEPTH` (never a truncated chain).
pub(super) async fn build_chain_on(
    conn: &mut sqlx::PgConnection,
    namespace: &str,
    governance: bool,
) -> StoreResult<Vec<String>> {
    let mut chain = vec!["*".to_string()];
    if namespace == "*" {
        return Ok(chain);
    }
    let hierarchy = slash_chain(namespace).map_err(over_depth)?;
    if let Some(root) = hierarchy.first().cloned() {
        let mut explicit_above: Vec<String> = Vec::new();
        let mut current = root;
        loop {
            let row: Option<(Option<String>,)> =
                sqlx::query_as("SELECT parent_namespace FROM namespace_meta WHERE namespace = $1")
                    .bind(&current)
                    .fetch_optional(&mut *conn)
                    .await
                    .map_err(|e| to_store_err("namespace chain parent lookup", e))?;
            let Some(p) = row.and_then(|(p,)| p) else {
                break;
            };
            if p == "*" || explicit_above.contains(&p) || hierarchy.contains(&p) {
                break;
            }
            if governance {
                let parent_owner = standard_owner(conn, &p).await?;
                let entitled = match parent_owner {
                    None => true,
                    Some(po) => {
                        standard_owner(conn, &current).await?.as_deref() == Some(po.as_str())
                    }
                };
                if !entitled {
                    pg_warn_governance_graft_excluded(namespace, &current, &p);
                    break;
                }
            }
            admit_explicit_parent(&explicit_above).map_err(over_depth)?;
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

/// #4492 — the postgres reader for the bind-time chain-depth refusal (the
/// decision is `crate::governance::bind_chain_depth`, shared with sqlite):
/// the `namespace_meta` link column, every hop counted whoever owns it.
/// Called in the bind's transaction AFTER the bind advisory lock, before the
/// upsert, so two binds cannot race past it.
///
/// # Errors
///
/// `InvalidInput` with the fixed #4492 text, or a storage fault (the bind is
/// refused, fail closed).
pub(super) async fn admit_bind_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    namespace: &str,
    new_parent: Option<&str>,
) -> StoreResult<()> {
    use crate::governance::bind_chain_depth::{
        BIND_CHAIN_OVER_DEPTH, LinkRow, bind_exceeds_chain_depth,
    };
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT nm.namespace, nm.parent_namespace FROM namespace_meta nm \
         WHERE nm.parent_namespace IS NOT NULL",
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| to_store_err("bind chain-depth link graph", e))?;
    let links: Vec<LinkRow> = rows
        .into_iter()
        .map(|(namespace, parent)| LinkRow { namespace, parent })
        .collect();
    if bind_exceeds_chain_depth(&links, namespace, new_parent) {
        return Err(StoreError::InvalidInput {
            detail: BIND_CHAIN_OVER_DEPTH.to_string(),
        });
    }
    Ok(())
}

/// #4715 — every stored explicit `parent_namespace` chain already past the
/// governance bound, read from any pool (the doctor probe builds its own
/// one-connection pool). The decision is the one shared
/// `governance::bind_chain_depth::over_depth_chains` (root segments only, every
/// hop counted), so the backends cannot disagree.
///
/// # Errors
///
/// The sqlx failure (never reported as "no over-depth chain").
pub async fn list_over_depth_chains_pg(
    pool: &sqlx::PgPool,
) -> Result<Vec<crate::governance::bind_chain_depth::OverDepthChain>, sqlx::Error> {
    use crate::governance::bind_chain_depth::{LinkRow, over_depth_chains};
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT namespace, parent_namespace FROM namespace_meta \
         WHERE parent_namespace IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    let links: Vec<LinkRow> = rows
        .into_iter()
        .map(|(namespace, parent)| LinkRow { namespace, parent })
        .collect();
    Ok(over_depth_chains(&links))
}
