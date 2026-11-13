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
        // #9178 D: the one shared snapshot statement (#8169, #9218).
        pg_replace_archive_snapshot_in_tx(
            tx,
            id,
            crate::models::field_names::ARCHIVE_REASON_CONSOLIDATE,
            "consolidate",
        )
        .await?;
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

#[cfg(test)]
mod record_stop_9178_tests {
    use super::*;
    use crate::models::{ConfidenceSource, LifecycleState, Memory, MemoryKind, Tier};
    use crate::store::{CallerContext, MemoryStore};

    /// The operator id the test engages the record stop as.
    const ISSUER: &str = "ai:operator-9178";
    const AGENT: &str = "ai:consolidate-9178";

    fn source(id: &str, namespace: &str) -> Memory {
        Memory {
            cid: None,
            valid_from: None,
            valid_until: None,
            id: id.to_string(),
            tier: Tier::Mid,
            namespace: namespace.to_string(),
            title: "record-stop source".to_string(),
            content: "text the stopped plane must not move".to_string(),
            tags: Vec::new(),
            priority: 5,
            confidence: 1.0,
            source: "user".to_string(),
            access_count: 0,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            last_accessed_at: None,
            expires_at: None,
            metadata: serde_json::json!({ "agent_id": AGENT }),
            reflection_depth: 0,
            memory_kind: MemoryKind::Observation,
            entity_id: None,
            persona_version: None,
            citations: Vec::new(),
            source_uri: None,
            source_span: None,
            confidence_source: ConfidenceSource::CallerProvided,
            confidence_signals: None,
            confidence_decayed_at: None,
            version: 1,
            lifecycle_state: LifecycleState::Open,
        }
    }

    /// #9178 B — the helper refuses on its OWN record-stop recheck (B9), not
    /// only behind the caller's entry gate: with the stop engaged between
    /// admission and the helper, it returns the exact `Stopped` error and
    /// writes nothing. Skips only when the URL is unset.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn archive_consolidate_source_refuses_when_stopped_9178() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            return;
        };
        let store = PostgresStore::connect(&url).await.unwrap();
        let ctx = CallerContext::for_agent(AGENT);
        let namespace = format!("rs9178-{}", uuid::Uuid::new_v4());
        let seeded = uuid::Uuid::new_v4().to_string();
        let id = store
            .store(&ctx, &source(&seeded, &namespace))
            .await
            .unwrap();

        let mut tx = store.pool().begin().await.unwrap();
        store
            .record_stop
            .engage(ISSUER, crate::store::record_stop::SCOPE_RECORD_PLANE);
        let refused = store.archive_consolidate_source_in_tx(&mut tx, &id).await;
        store.record_stop.release();
        let err = refused.err().map(|e| e.to_string());
        tx.rollback().await.unwrap();
        assert_eq!(
            err.as_deref(),
            Some(
                "substrate record plane stopped by ai:operator-9178 (scope=record-plane); \
                 mutating operations refused until resume"
            ),
        );
        let live: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memories WHERE id = $1")
            .bind(&id)
            .fetch_one(store.pool())
            .await
            .unwrap();
        let archived: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM archived_memories WHERE id = $1")
                .bind(&id)
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert_eq!((live, archived), (1, 0), "the refused helper wrote nothing");
        store.pool().close().await;
    }
}
