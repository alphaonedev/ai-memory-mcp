// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3124 R4 — the postgres twin of [`crate::storage::reown`]: re-stamp
//! `metadata.agent_id` over a namespace (or every namespace), bump `version` /
//! `updated_at`, and append ONE `memory.reowned` signed-chain row in the same
//! transaction.
//!
//! # Why it is its own module
//!
//! `src/store/postgres.rs` sits at its `qual_10_module_size_ceiling` budget,
//! and the lane brief mandates a submodule over a private ceiling bump — the
//! `postgres/api_key_revoke_3529.rs` precedent. The trait arm in
//! `postgres.rs` takes the record-stop gate and forwards here.

use super::{
    CallerContext, PgSignedEventInsert, PostgresStore, StoreError, StoreResult,
    pg_append_signed_event_with_chain_in_tx, to_store_err,
};

impl PostgresStore {
    /// #3124 R4 — the reown sweep. Same contract as the sqlite funnel:
    /// `select` / `--all-namespaces` / `version` + `updated_at` bump / one
    /// `memory.reowned` chain row in the same transaction / record-stop
    /// refusal.
    ///
    /// # Errors
    ///
    /// An invalid `to_id`, the record-stop refusal, or any transaction /
    /// query / chain-append failure.
    pub(super) async fn reown_pg(
        &self,
        ctx: &CallerContext,
        namespace: Option<&str>,
        to_id: &str,
        select: crate::storage::ReownSelect,
        dry_run: bool,
    ) -> StoreResult<crate::storage::ReownReport> {
        // v0.8.0 #1709/#1720 WS-B B2 — postgres twin of
        // `crate::storage::reown`. `metadata` is JSONB; `jsonb_set` on
        // the single `{agent_id}` path preserves every other key, and
        // the `agent_id_idx` STORED generated column re-projects the new
        // owner automatically. `to_id` is validated identically so a
        // malformed owner can never be written on either backend.
        // #3124 R4 — `select` / `--all-namespaces` / version + updated_at
        // bump / one `memory.reowned` chain row in the same transaction /
        // record-stop refusal: identical contract to the sqlite funnel.
        crate::validate::validate_agent_id(to_id).map_err(|e| StoreError::InvalidInput {
            detail: format!("reown: invalid --to agent_id: {e}"),
        })?;
        if !dry_run {
            self.gate_record_stop().await?;
        }

        let owner_filter = match select {
            crate::storage::ReownSelect::All => String::new(),
            crate::storage::ReownSelect::Owned => {
                " AND metadata ? 'agent_id' AND COALESCE(metadata ->> 'agent_id', '') != ''"
                    .to_string()
            }
            crate::storage::ReownSelect::OnlyUnowned => format!(
                " AND {}",
                crate::identity::owner_stamp::PG_UNSTAMPED_PREDICATE
            ),
        };
        // $1 = namespace (when scoped); the UPDATE appends $2 = to_id.
        let ns_clause = if namespace.is_some() {
            "namespace = $1"
        } else {
            "TRUE"
        };

        let count_sql = format!("SELECT COUNT(*) FROM memories WHERE {ns_clause}{owner_filter}");
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql);
        if let Some(ns) = namespace {
            count_q = count_q.bind(ns);
        }
        let matched: i64 = count_q
            .fetch_one(&self.pool)
            .await
            .map_err(|e| to_store_err("reown count", e))?;
        let matched = usize::try_from(matched).unwrap_or(usize::MAX);

        if dry_run {
            return Ok(crate::storage::ReownReport {
                matched,
                rewritten: 0,
                dry_run: true,
                select,
            });
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("reown begin", e))?;
        let to_param = if namespace.is_some() { "$2" } else { "$1" };
        let update_sql = format!(
            "UPDATE memories \
             SET metadata = jsonb_set(metadata, '{{agent_id}}', to_jsonb({to_param}::text)), \
                 version = version + 1, updated_at = NOW() \
             WHERE {ns_clause}{owner_filter}"
        );
        let mut update_q = sqlx::query(&update_sql);
        if let Some(ns) = namespace {
            update_q = update_q.bind(ns);
        }
        let rewritten = update_q
            .bind(to_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err("reown update", e))?
            .rows_affected();
        let rewritten = usize::try_from(rewritten).unwrap_or(usize::MAX);

        let now = chrono::Utc::now();
        let action_kind = crate::signed_events::event_types::MEMORY_REOWNED;
        let payload = crate::storage::reown_audit_payload(namespace, to_id, select, rewritten);
        let ph = crate::signed_events::payload_hash(payload.as_bytes());
        let cause = crate::signed_events::compute_cause_hash(
            &ctx.agent_id,
            action_kind,
            namespace.unwrap_or(crate::storage::REOWN_ALL_NAMESPACES_TOKEN),
            &payload,
        );
        let event = crate::signed_events::SignedEvent::with_daemon_signature(
            ph,
            ctx.agent_id.clone(),
            action_kind.to_string(),
            now.to_rfc3339(),
            Some(&cause),
        );
        pg_append_signed_event_with_chain_in_tx(
            &mut tx,
            PgSignedEventInsert {
                id: &event.id,
                agent_id: &event.agent_id,
                event_type: &event.event_type,
                payload_hash: &event.payload_hash,
                signature: event.signature.as_deref(),
                attest_level: &event.attest_level,
                timestamp: now,
                cause_hash: event.cause_hash.as_deref(),
            },
        )
        .await
        .map_err(|e| to_store_err("reown append signed_event", e))?;
        tx.commit()
            .await
            .map_err(|e| to_store_err("reown commit", e))?;
        tracing::warn!(
            target: "ai_memory::reown",
            namespace = namespace.unwrap_or(crate::storage::REOWN_ALL_NAMESPACES_TOKEN),
            to = %to_id,
            select = select.as_str(),
            rewritten,
            actor = %ctx.agent_id,
            "reown: an operator re-stamped metadata.agent_id; a memory.reowned signed-chain \
             row was appended in the same transaction (#3124)"
        );

        Ok(crate::storage::ReownReport {
            matched,
            rewritten,
            dry_run: false,
            select,
        })
    }
}
