// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4478 — the ONE postgres `set_namespace_standard` body, shared by the SAL
//! trait method (a tenant / admin caller, #3758 + #4356 via
//! `ns_standard_ancestor_4356::set_gate_in_tx`) and the federated
//! `namespace_meta[]` apply, which must NOT ride the admin bypass: it runs the
//! #4356 ancestor-owner gate for the agent the pushing peer is authenticated
//! to act for (`crate::federation::ns_meta_ancestor_gate`). Both gates read
//! inside the bind's transaction after the bind advisory lock, so the two
//! funnels serialise against each other and against local binds. Moved out of
//! `postgres.rs` verbatim apart from the gate dispatch (qual_10 budget).

use super::{
    PostgresStore, SQL_SELECT_MEMORY_ID_BY_ID, StoreResult, governance_chain_4477,
    ns_standard_ancestor_4356, pg_advisory_xact_lock_key, pg_auto_detect_parent,
    pg_namespace_standard_binding, to_store_err,
};
use crate::ns_standard_ancestor::{GoverningAncestor, PG_STANDARD_BIND_LOCK_KEY, needs_ancestor};
use crate::store::{CallerContext, StoreError};

/// The federated actor resolver: the bound standard memory's stored owner in,
/// the authenticated acting agent out (`None` = cannot be established).
pub(crate) type ActorFor<'a> = &'a (dyn Fn(Option<&str>) -> Option<String> + Sync);

/// Which authorization the SET runs.
pub(crate) enum BindGate<'a> {
    /// A SAL caller: #3758 rebind gate + #4356 ancestor gate (admin bypasses).
    Caller(&'a CallerContext),
    /// #4478 — a federated apply: the #4356 ancestor gate on a first bind for
    /// the peer's authenticated actor; never bypassed.
    Federated(ActorFor<'a>),
}

/// #4478 — the federated gate inside `tx`: lock, then (first bind / severed
/// repair only) the governing ancestor and the bound memory's owner.
async fn federated_gate_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_for: ActorFor<'_>,
    namespace: &str,
    standard_id: &str,
) -> StoreResult<()> {
    pg_advisory_xact_lock_key(tx, PG_STANDARD_BIND_LOCK_KEY)
        .await
        .map_err(|e| to_store_err("federated set_namespace_standard bind lock", e))?;
    let binding = pg_namespace_standard_binding(tx, namespace).await?;
    if !needs_ancestor(&binding) {
        return Ok(());
    }
    let ancestor: GoverningAncestor =
        ns_standard_ancestor_4356::governing_ancestor_in_tx(tx, namespace).await?;
    let owner: Option<Option<String>> =
        sqlx::query_scalar("SELECT m.metadata->>'agent_id' FROM memories m WHERE m.id = $1")
            .bind(standard_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| to_store_err("federated set_namespace_standard owner", e))?;
    let actor = actor_for(owner.flatten().as_deref());
    crate::federation::ns_meta_ancestor_gate::federated_bind_admission(
        actor.as_deref(),
        namespace,
        &binding,
        &ancestor,
    )
    .map_err(|r| crate::store::set_refusal_to_store_err(r, namespace))
}

/// The SET body (see the module docs).
///
/// # Errors
///
/// `NotFound` for an absent standard memory, `InvalidInput` for a
/// self-parent, `PermissionDenied` for a gate refusal, or the storage fault.
pub(crate) async fn set_namespace_standard_gated(
    store: &PostgresStore,
    gate: BindGate<'_>,
    namespace: &str,
    standard_id: &str,
    parent: Option<&str>,
) -> StoreResult<()> {
    // Wave-2 B7' — sqlite twin `db::set_namespace_standard` gates (ERRORS-09).
    store.gate_record_stop().await?;
    // Require the standard memory to exist first (parity with
    // sqlite db::set_namespace_standard).
    let exists: Option<(String,)> = sqlx::query_as(SQL_SELECT_MEMORY_ID_BY_ID)
        .bind(standard_id)
        .fetch_optional(&store.pool)
        .await
        .map_err(|e| to_store_err("set_namespace_standard verify memory", e))?;
    if exists.is_none() {
        return Err(StoreError::NotFound {
            id: standard_id.to_string(),
        });
    }
    if parent.is_some_and(|p| p == namespace) {
        return Err(StoreError::InvalidInput {
            detail: "namespace cannot be its own parent".to_string(),
        });
    }
    // #3188 — CROSS-BACKEND PARITY. When the caller declares no parent,
    // resolve the '-'-prefix ancestor EXACTLY as the sqlite twin
    // (`db::set_namespace_standard` → `db::auto_detect_parent`) so both
    // backends bind the SAME `parent_namespace`. `pg_auto_detect_parent`
    // FAILS CLOSED on a DB fault (it does not swallow the error into "no
    // parent"), matching the sqlite `auto_detect_parent` contract.
    let resolved_parent: Option<String> = match parent {
        Some(p) => Some(p.to_string()),
        None => pg_auto_detect_parent(&store.pool, namespace).await?,
    };
    // #3758 rebind gate + #4356 bind lock and ancestor-owner gate (or the
    // #4478 federated gate), read in THIS transaction with the upsert (#3237
    // item 5 TOCTOU discipline).
    let mut tx = store
        .pool
        .begin()
        .await
        .map_err(|e| to_store_err("set_namespace_standard begin", e))?;
    match gate {
        BindGate::Caller(ctx) => {
            ns_standard_ancestor_4356::set_gate_in_tx(&mut tx, ctx, namespace).await?;
        }
        BindGate::Federated(actor_for) => {
            federated_gate_in_tx(&mut tx, actor_for, namespace, standard_id).await?;
        }
    }
    // #4492 — the bind-time chain-depth admission, for every gate (the
    // federated apply included), under the same lock and in the same tx.
    governance_chain_4477::admit_bind_in_tx(&mut tx, namespace, resolved_parent.as_deref()).await?;
    sqlx::query(
        "INSERT INTO namespace_meta (namespace, standard_id, updated_at, parent_namespace)
         VALUES ($1, $2, NOW(), $3)
         ON CONFLICT (namespace) DO UPDATE
            SET standard_id = EXCLUDED.standard_id,
                updated_at = EXCLUDED.updated_at,
                parent_namespace = EXCLUDED.parent_namespace",
    )
    .bind(namespace)
    .bind(standard_id)
    .bind(resolved_parent.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(|e| to_store_err("set_namespace_standard", e))?;
    tx.commit()
        .await
        .map_err(|e| to_store_err("set_namespace_standard commit", e))?;
    Ok(())
}

impl PostgresStore {
    /// #4478 — the federated `namespace_meta[]` apply: the same SET body,
    /// gated by the #4356 ancestor-owner check for the agent the pushing peer
    /// is authenticated to act for (`actor_for`), never by the admin bypass.
    ///
    /// # Errors
    ///
    /// As [`set_namespace_standard_gated`]; a gate refusal is
    /// `PermissionDenied` with the shared fixed refusal text.
    pub(crate) async fn set_namespace_standard_federated(
        &self,
        actor_for: ActorFor<'_>,
        namespace: &str,
        standard_id: &str,
        parent: Option<&str>,
    ) -> StoreResult<()> {
        set_namespace_standard_gated(
            self,
            BindGate::Federated(actor_for),
            namespace,
            standard_id,
            parent,
        )
        .await
    }
}
