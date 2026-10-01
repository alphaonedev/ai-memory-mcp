// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4356 — the postgres reader behind the ancestor-owner bind gate. The verdict
//! lives once in [`crate::ns_standard_ancestor`]; this module only reads the
//! governance chain's levels through the supplied transaction (so the read
//! shares the bind's upsert transaction — the fail-closed floor) and takes the
//! bind's serialising advisory lock. Own module for the qual_10 budget reason
//! of `parity_3064`.

use super::{
    StoreResult, build_namespace_chain_in_tx, pg_advisory_xact_lock_key,
    pg_namespace_standard_binding, to_store_err,
};
use crate::ns_standard_ancestor::{
    AncestorLevel, GoverningAncestor, PG_STANDARD_BIND_LOCK_KEY, classify_standard_metadata,
    needs_ancestor, select_governing_ancestor, set_admission,
};
use crate::store::CallerContext;

/// One level through `tx`. The bound standard's `metadata` is classified by
/// the SAME shared classifier the sqlite reader uses (#4356 CR1): a corrupt
/// `governance` blob (or a non-string owner) is `Severed`, never `NoPolicy`.
/// (`memories.metadata` is CHECK-constrained to a JSON object on postgres, so
/// the non-object shapes are sqlite-only; the classifier still covers them.)
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
    let mem: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT metadata FROM memories WHERE id = $1")
            .bind(&standard_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| to_store_err("ns_standard_ancestor standard", e))?;
    Ok(mem.map_or(AncestorLevel::Severed, |(m,)| {
        classify_standard_metadata(&m)
    }))
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

/// [`governing_ancestor_in_tx`] in a fresh pool transaction (the HTTP arm's
/// pre-write probe; the adapter's [`set_gate_in_tx`] is the authoritative,
/// serialised re-check).
///
/// # Errors
///
/// Any storage fault.
pub(super) async fn governing_ancestor_pool(
    pool: &sqlx::PgPool,
    namespace: &str,
) -> StoreResult<GoverningAncestor> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| to_store_err("namespace_governing_ancestor begin", e))?;
    governing_ancestor_in_tx(&mut tx, namespace).await
}

/// #3758 + #4356 — the SET gate inside the bind's own transaction `tx`.
///
/// FIRST takes the transaction-scoped advisory lock
/// [`PG_STANDARD_BIND_LOCK_KEY`] (every SET, bypass included, so an
/// operator's ancestor bind and a caller's child bind serialise). Under READ
/// COMMITTED every later statement then sees any bind that held the lock
/// before this one as COMMITTED, so two concurrent first binds cannot both
/// pass on a stale chain (#4023/#4447 TOCTOU class). Released by
/// COMMIT/ROLLBACK; single key, trivially deadlock-free (CONCURRENCY-04).
///
/// # Errors
///
/// [`crate::store::StoreError::PermissionDenied`] with the shared refusal
/// text, or the storage fault (fail-closed).
pub(super) async fn set_gate_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ctx: &CallerContext,
    namespace: &str,
) -> StoreResult<()> {
    pg_advisory_xact_lock_key(tx, PG_STANDARD_BIND_LOCK_KEY)
        .await
        .map_err(|e| to_store_err("set_namespace_standard bind lock", e))?;
    if ctx.bypass_visibility {
        return Ok(());
    }
    let binding = pg_namespace_standard_binding(tx, namespace).await?;
    let ancestor = if needs_ancestor(&binding) {
        governing_ancestor_in_tx(tx, namespace).await?
    } else {
        GoverningAncestor::None
    };
    set_admission(
        ctx.effective_principal(),
        false,
        namespace,
        &binding,
        &ancestor,
    )
    .map_err(|r| crate::store::set_refusal_to_store_err(r, namespace))
}
