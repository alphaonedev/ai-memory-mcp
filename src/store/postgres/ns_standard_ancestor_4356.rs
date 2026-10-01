// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4356 — the postgres reader behind the ancestor-owner bind gate. The verdict
//! lives once in [`crate::ns_standard_ancestor`]; this module only reads the
//! governance chain's levels through the supplied transaction (so the read
//! shares a snapshot with the bind's upsert — the fail-closed floor). Own
//! module for the qual_10 budget reason of `parity_3064`.

use super::{StoreResult, build_namespace_chain_in_tx, to_store_err};
use crate::ns_standard_ancestor::{
    AncestorLevel, GoverningAncestor, normalise_owner, select_governing_ancestor,
};

/// One level through `tx`. `jsonb_typeof(... ) <> 'null'` mirrors the sqlite
/// `json_extract IS NOT NULL` probe: a bound standard with no (or a JSON-null)
/// `metadata.governance` is `NoPolicy`.
async fn read_level(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    namespace: &str,
) -> StoreResult<AncestorLevel> {
    let meta: Option<(Option<String>,)> =
        sqlx::query_as("SELECT standard_id FROM namespace_meta WHERE namespace = $1")
            .bind(namespace)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| to_store_err("ns_standard_ancestor meta", e))?;
    let Some((bound,)) = meta else {
        return Ok(AncestorLevel::Absent);
    };
    let Some(standard_id) = bound else {
        return Ok(AncestorLevel::Severed);
    };
    let mem: Option<(bool, Option<String>)> = sqlx::query_as(
        "SELECT COALESCE(jsonb_typeof(metadata->'governance') <> 'null', FALSE), \
         metadata->>'agent_id' FROM memories WHERE id = $1",
    )
    .bind(&standard_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| to_store_err("ns_standard_ancestor standard", e))?;
    Ok(match mem {
        None => AncestorLevel::Severed,
        Some((false, _)) => AncestorLevel::NoPolicy,
        Some((true, owner)) => AncestorLevel::Governing {
            owner: normalise_owner(owner),
        },
    })
}

/// The nearest governing ancestor of `namespace` (target and `*` excluded) on
/// the GOVERNANCE chain, read inside `tx`.
///
/// # Errors
///
/// Any storage fault (the caller refuses — fail-closed).
pub(super) async fn governing_ancestor_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    namespace: &str,
) -> StoreResult<GoverningAncestor> {
    let chain = build_namespace_chain_in_tx(tx, namespace, true).await?;
    let mut levels: Vec<StoreResult<AncestorLevel>> = Vec::new();
    for n in chain
        .iter()
        .rev()
        .filter(|n| n.as_str() != namespace && n.as_str() != "*")
    {
        let lv = read_level(tx, n).await;
        let stop = !matches!(lv, Ok(AncestorLevel::Absent | AncestorLevel::NoPolicy));
        levels.push(lv);
        if stop {
            break;
        }
    }
    select_governing_ancestor(levels)
}
