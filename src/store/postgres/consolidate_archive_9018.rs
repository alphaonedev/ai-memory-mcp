// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9018 — archive-first disposition of a consolidate SOURCE on postgres when
//! the tombstone sub-flag is OFF (the legacy arm).
//!
//! Before #9018 that arm ran a bare `DELETE FROM memories` per source, so the
//! merged-away text had no archive row and no recovery path, and the
//! source's `memory_links` were reaped by the cascade. The SQLite twin now
//! routes through `storage::archive_memory` (`archive_memory_no_tx`); this is
//! the postgres twin with the same steps in the caller's transaction:
//! snapshot the row into `archived_memories` (last-wins, the sqlite
//! `INSERT OR REPLACE` contract), snapshot its links, sever any namespace
//! standard bound to it, append the ARCHIVE revision leaf when append-only is
//! on, delete the live row, and drop its AGE projection. Own module because
//! `postgres.rs` sits at its `qual_10_module_size_ceiling` budget.

use super::*;

impl PostgresStore {
    /// Move one consolidate source into the archive inside `tx`.
    ///
    /// Returns the audit anchor of the namespace-standard sever, which the
    /// caller emits only after its COMMIT (`pg_commit_and_emit`).
    ///
    /// # Errors
    ///
    /// [`StoreError::Stopped`] when the record plane is stopped, or any SQL
    /// failure; the caller's transaction then rolls back, so the
    /// consolidated summary row is not committed either.
    pub(super) async fn archive_consolidate_source_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: &str,
    ) -> StoreResult<crate::governance::audit::PendingAuditAnchor> {
        // Record-stop recheck inside the tx (B9): the caller gated at entry,
        // but this helper writes `archived_memories` + `memories` itself, so
        // it refuses on its own rather than trusting every future caller.
        self.gate_record_stop_in_transaction()?;
        sqlx::query(SQL_DELETE_ARCHIVED_MEMORY_BY_ID)
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(|e| to_store_err("consolidate clear prior archive record", e))?;
        sqlx::query(SQL_ARCHIVE_SNAPSHOT_LIVE_ROW)
            .bind(id)
            .bind(crate::models::field_names::ARCHIVE_REASON_CONSOLIDATE)
            .execute(&mut **tx)
            .await
            .map_err(|e| to_store_err("consolidate archive source", e))?;
        crate::store::postgres_parity::archive_links_for_memory_in_tx(tx, id).await?;
        let (_, anchor) = pg_sever_namespace_standards_in_tx(tx, id)
            .await
            .map_err(|e| to_store_err("consolidate namespace_meta sever", e))?;
        if crate::config::append_only_enabled()
            && let Some((ns, ver)) = sqlx::query_as::<_, (String, i64)>(SQL_SELECT_NS_VERSION_BY_ID)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| to_store_err("consolidate read row for leaf", e))?
        {
            pg_emit_revision_leaf_if_enabled(
                tx,
                id,
                crate::revisions::RecordKind::Archive,
                Some(ver),
                &ns,
                None,
                &Utc::now().to_rfc3339(),
            )
            .await
            .map_err(|e| to_store_err("consolidate archive revision leaf", e))?;
        }
        sqlx::query(SQL_DELETE_MEMORY_BY_ID)
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(|e| to_store_err("consolidate delete source", e))?;
        // #1783 — remove the merged-away source's AGE projection in this tx
        // so kg_query/find_paths don't keep a ghost edge to it.
        if matches!(self.kg_backend, KgBackend::Age) {
            unproject_memory_from_age(tx, id).await?;
        }
        Ok(anchor)
    }
}
