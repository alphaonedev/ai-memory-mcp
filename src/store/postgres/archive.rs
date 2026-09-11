// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 U1/U1b — production archive core that composes in an existing
//! transaction. The ordinary archive verb owns begin/commit and bounded
//! retries; supersession will use this same core inside its create transaction.
//! No legacy update-with-archive parity path is used here.
//!
//! This preserves the ordinary archive's owner/inbox/admin policy. It does not
//! establish U1 supersession authority: that caller must additionally validate
//! hardened principal provenance, namespace/key, ids and time inside its write
//! transaction before invoking this core.

use super::{
    CallerContext, KgBackend, PostgresStore, REASON_UNSTAMPED_TENANT_ARCHIVE,
    SQL_ARCHIVE_ON_CONFLICT_LAST_WINS, SQL_SELECT_NS_VERSION_BY_ID, StoreError, StoreResult,
    pg_emit_revision_leaf_if_enabled, pg_sever_namespace_standards_in_tx, to_store_err,
    unproject_memory_from_age,
};
use crate::store::record_stop::gate_flag as gate_record_stop_cached;

impl PostgresStore {
    /// Archive within the caller's transaction; never begin, commit or retry it.
    ///
    /// The caller refreshes the durable record-stop state before opening the
    /// transaction. Recheck its cached flag here without borrowing a second pool
    /// connection while holding the write transaction (including max_connections=1).
    /// Owner probes, ordered row locks, snapshots, SEVER, G6 leaves and AGE
    /// unprojection remain part of this transaction (CONCURRENCY-04, ERRORS-02).
    /// Any error requires the caller to roll back the entire transaction.
    pub(crate) async fn archive_by_ids_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &CallerContext,
        ids: &[String],
        archive_reason: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> StoreResult<usize> {
        gate_record_stop_cached(&self.record_stop)?;
        let mut moved = 0usize;

        // v1.0.0 #3296 A6 (CONCURRENCY-04) — lock rows in a GLOBAL order. The
        // per-id `FOR UPDATE` owner probe below (`SQL_SELECT_MEMORY_ROW_BY_ID`
        // gained `FOR UPDATE` in the same PR that shares the const across
        // update/delete/archive) locks in the CALLER-SUPPLIED id order, so two
        // overlapping batches submitted in opposite order can deadlock. Locking
        // the id set in a fixed (sorted) order breaks the cycle. Sorting only
        // reorders the work; `moved` and the all-or-nothing tx are unchanged.
        let mut ordered: Vec<&str> = ids.iter().map(String::as_str).collect();
        ordered.sort_unstable();

        for id in ordered {
            // #3193 (SECURITY-high, 2026-08-22) — SAL-side caller-owns gate,
            // the archive-verb sibling of the #1412/#1628 gates on the trait
            // `update` / `delete`. Pre-fix this funnel discarded its
            // `_ctx: &CallerContext` entirely and the INSERT..SELECT below
            // matched on `WHERE id = $3` with NO owner predicate, so ANY
            // authenticated tenant on a postgres-backed daemon could
            // bulk-soft-delete up to `max_batch` of ANOTHER tenant's live
            // rows through `POST /api/v1/archive` (links cascaded; the rows
            // vanished from get/list/search/recall). The sqlite branch has
            // refused since #940 via `db::archive_memory_for_caller`; #3115
            // fixed only that side of this class.
            //
            // Runs INSIDE the batch transaction (`FOR UPDATE` owner+inbox
            // probe). A genuinely-absent id is `NotFound` → silent
            // `continue` (the count-delta contract the handler relies on;
            // not an existence oracle). A LIVE row owned by someone else
            // raises `PermissionDenied`. Inbox-target (`metadata.target_agent_id`
            // == caller) is permitted — sqlite #940 parity (Fable #3243
            // item 1). Admin/operator lanes (`ctx.bypass_visibility`) skip
            // the gate, exactly as they do on update/delete.
            match Self::assert_caller_owns_for_mutation_on(
                &mut **tx,
                ctx,
                id,
                "archive",
                REASON_UNSTAMPED_TENANT_ARCHIVE,
                true,
            )
            .await
            {
                Ok(()) => {}
                Err(StoreError::NotFound { .. }) => continue,
                Err(e) => return Err(e),
            }
            let insert_result = sqlx::query(&format!(
                "INSERT INTO archived_memories (
                    id, tier, namespace, title, content, tags, priority, confidence,
                    source, access_count, created_at, updated_at, last_accessed_at,
                    expires_at, archived_at, archive_reason, metadata,
                    embedding, embedding_dim, embedding_space, original_tier, original_expires_at,
                    -- #1025 (CRITICAL, 2026-05-21) — full v0.7.0 column carry.
                    reflection_depth, atomised_into, atom_of, memory_kind,
                    entity_id, persona_version, citations, source_uri, source_span,
                    confidence_source, confidence_signals, confidence_decayed_at,
                    -- #2196 - carry lifecycle_state through the manual archive so a
                    -- non-open state survives archive->restore (postgres parity).
                    mentioned_entity_id, version, lifecycle_state, encrypted_envelope, kind_provenance, valid_from, valid_until, cid, cid_genesis
                )
                SELECT id, tier, namespace, title, content, tags, priority, confidence,
                       source, access_count, created_at, updated_at, last_accessed_at,
                       expires_at, $1::timestamptz, $2::text, metadata,
                       embedding, embedding_dim, embedding_space, tier, expires_at,
                       reflection_depth, atomised_into, atom_of, memory_kind,
                       entity_id, persona_version, citations, source_uri, source_span,
                       confidence_source, confidence_signals, confidence_decayed_at,
                       mentioned_entity_id, version, lifecycle_state, encrypted_envelope, kind_provenance, valid_from, valid_until, cid, cid_genesis
                FROM memories WHERE id = $3
                  AND ($4::bool
                       OR metadata->>'agent_id' = $5
                       OR metadata->>'target_agent_id' = $5)
                -- #2195 - LAST-WINS re-archive parity with sqlite INSERT OR REPLACE.
                -- $4 bypass / $5 caller: owner-predicated write so a concurrent
                -- re-own cannot archive a row the FOR UPDATE probe no longer owns
                -- (Fable #3243 item 4). Bypass short-circuits the owner/inbox arms.
                {SQL_ARCHIVE_ON_CONFLICT_LAST_WINS}"
            ))
            .bind(now)
            .bind(archive_reason)
            .bind(id)
            .bind(ctx.bypass_visibility)
            .bind(ctx.effective_principal())
            .execute(&mut **tx)
            .await
            .map_err(|e| to_store_err("archive_by_ids insert", e))?;
            // v1.0.0 #3296 A2 — only count an id whose live row was ACTUALLY
            // archived. On the `bypass_visibility` (admin/CLI) lane
            // `assert_caller_owns_for_mutation_on` returns `Ok(())` immediately
            // WITHOUT proving the row exists, so a nonexistent id reached here
            // and `moved += 1` ran even though the owner-predicated
            // INSERT..SELECT matched 0 live rows — contradicting the trait
            // contract ("an id with no live row is skipped and not counted").
            // Skipping on a zero-row insert also protects the non-bypass lane
            // against a concurrent delete between the probe and this write. The
            // link snapshot / namespace sever / delete / AGE unprojection below
            // are all no-ops for an id with no live row, so `continue` is safe.
            if insert_result.rows_affected() == 0 {
                continue;
            }
            // #1771 (5-agent vote 4d3ea1c5) — snapshot this memory's
            // `memory_links` into `archived_memory_links` BEFORE the
            // same-tx cascade delete reaps them (FK `ON DELETE CASCADE`).
            // Postgres twin of the SQLite `archive_links_for_memory`
            // snapshot wired into `archive_memory_no_tx`. Idempotent via
            // the PK `ON CONFLICT`.
            //
            // v1.0.0 #3177 — the statement moved to
            // [`crate::store::postgres_parity::archive_links_for_memory_in_tx`]
            // and this call site now SHARES it with the `size_gc` archive
            // branch. That branch had a hand-absent twin (it snapshotted
            // nothing), which is exactly the failure mode a second copy of a
            // statement invites; one definition means the next archiving path
            // cannot forget the edges.
            crate::store::postgres_parity::archive_links_for_memory_in_tx(tx, id).await?;
            // #2503 — SEVER any namespace_meta binding pointing at this row,
            // parity with BOTH sqlite archive funnels (`archive_memory_no_tx`
            // / `archive_memory_for_caller`), which have mirrored `delete`'s
            // cleanup since #1642. This pg funnel never did: archiving a
            // standard memory on postgres left the binding pointing at a row
            // that is no longer in `memories` — another arm of the #2493
            // class, in the same direction as `apply_remote_deletion`. Runs
            // INSIDE the per-batch tx so the sever commits atomically with the
            // archive+delete it accompanies.
            //
            // #3290 — route through the shared helper so this archive funnel
            // emits the WARN + signed `SUBSTRATE_NAMESPACE_STANDARD_SEVERED`
            // event, at parity with the sqlite archive twins
            // (`archive_memory_no_tx` / `archive_memory_for_caller`, which both
            // call `sever_namespace_standards`) — previously a bare, silent
            // UPDATE.
            pg_sever_namespace_standards_in_tx(tx, id)
                .await
                .map_err(|e| to_store_err("archive_by_ids: namespace_meta sever", e))?;
            // APPEND-ONLY-SANCTIONED (#1823 G6) — capture-then-compact:
            // append ONE identity-only ARCHIVE leaf IN THIS tx BEFORE the
            // delete (the cold-storage copy already landed above). Gated →
            // flag-OFF unchanged.
            if crate::config::append_only_enabled()
                && let Some((ns, ver)) =
                    sqlx::query_as::<_, (String, i64)>(SQL_SELECT_NS_VERSION_BY_ID)
                        .bind(id)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(|e| to_store_err("archive_by_ids read row for leaf", e))?
            {
                pg_emit_revision_leaf_if_enabled(
                    tx,
                    id,
                    crate::revisions::RecordKind::Archive,
                    Some(ver),
                    &ns,
                    None,
                    &now.to_rfc3339(),
                )
                .await
                .map_err(|e| to_store_err("append archive revision leaf", e))?;
            }
            sqlx::query(
                "DELETE FROM memories WHERE id = $1 \
                 AND ($2::bool \
                      OR metadata->>'agent_id' = $3 \
                      OR metadata->>'target_agent_id' = $3)",
            )
            .bind(id)
            .bind(ctx.bypass_visibility)
            .bind(ctx.effective_principal())
            .execute(&mut **tx)
            .await
            .map_err(|e| to_store_err("archive_by_ids delete", e))?;
            // #2315 — AGE unprojection parity. This was the ONLY hard-delete
            // path that skipped `unproject_memory_from_age` (delete / forget /
            // apply_remote_deletion / consolidate / run_gc / size_gc all call
            // it), so a manually-archived memory left a ghost `:Memory` node +
            // incident edges in the `memory_graph` projection that AGE-routed
            // kg_query kept returning — a live-looking edge to a non-live
            // memory. Same-tx DETACH DELETE, mirroring the forget() shape.
            if matches!(self.kg_backend, KgBackend::Age) {
                unproject_memory_from_age(tx, id).await?;
            }
            moved += 1;
        }
        Ok(moved)
    }
}

#[cfg(test)]
mod tests;
