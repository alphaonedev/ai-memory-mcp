// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 transactional twin of storage::supersession.

use super::{CallerContext, Memory, PostgresStore, StoreError, StoreResult, to_store_err};
use crate::identity::supersession::{
    SupersessionDecision, SupersessionProposal, authorize_supersession,
};
use crate::storage::supersession::{
    SupersessionRequest, SupersessionResult, audit_failure, audit_refusal, decide, ruling_key,
};
use crate::storage::supersession_pending::{ProposalGate, is_supersession, proposal_of};
use crate::store::record_stop::gate_flag as gate_record_stop_cached;

impl PostgresStore {
    pub(super) async fn subkey_is_revoked_pg(
        &self,
        principal: &str,
        instance_key_id: &[u8],
    ) -> StoreResult<bool> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM agent_subkey_certs WHERE principal = $1 AND instance_key_id = $2 AND revoked)")
            .bind(principal).bind(instance_key_id).fetch_one(&self.pool).await.map_err(|e| to_store_err("subkey revocation lookup", e))
    }

    pub(super) async fn insert_subkey_cert_pg(
        &self,
        record: &crate::identity::attest_v2::SubkeyCertRecord,
    ) -> StoreResult<()> {
        self.gate_record_stop().await?;
        sqlx::query("INSERT INTO agent_subkey_certs (id, principal, instance_key_id, model_version_ref, not_before, not_after, signature, cert_bytes, revoked, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,FALSE,$9) ON CONFLICT (id) DO NOTHING")
            .bind(&record.id).bind(&record.principal).bind(&record.instance_key_id).bind(&record.model_version_ref)
            .bind(&record.not_before).bind(&record.not_after).bind(&record.signature).bind(&record.cert_bytes)
            .bind(chrono::Utc::now().to_rfc3339()).execute(&self.pool).await.map_err(|e| to_store_err("insert verified subkey cert", e))?;
        Ok(())
    }

    /// Fresh insertion and predecessor archive commit or roll back together.
    ///
    /// # Errors
    /// Propagates record-stop, validation, conflict and transactional failures.
    pub async fn store_with_supersession(
        &self,
        ctx: &CallerContext,
        memory: &Memory,
        embedding: Option<&[f32]>,
        space: Option<&str>,
        request: SupersessionRequest<'_>,
    ) -> StoreResult<SupersessionResult> {
        async {
            self.gate_record_stop().await?;
            let key = ruling_key(&memory.metadata)
                .map_err(|e| StoreError::InvalidInput {
                    detail: e.to_string(),
                })?
                .ok_or_else(|| StoreError::InvalidInput {
                    detail: "supersession store requires ruling_key".into(),
                })?;
            // A namespace+key lock also serializes creators when NO predecessor
            // exists. JSON tuple encoding is injective; hash collisions only serialize
            // unrelated writers. Acquire it before any memory row locks.
            let lock_key = serde_json::to_string(&("supersession-3587", &memory.namespace, key))
                .map_err(|e| StoreError::InvalidInput {
                    detail: e.to_string(),
                })?;
            let mut retry = super::tx_retry::TxRetry::new("store supersession");
            let result = loop {
                match self
                    .store_supersession_attempt(ctx, memory, embedding, space, request, &lock_key)
                    .await
                {
                    Ok(result) => break result,
                    Err(error) => retry.consider(error).await?,
                }
            };
            crate::cost::postgres::record_write_pg(&self.pool, memory, &result.id).await;
            result.audit(request, memory);
            Ok(result)
        }
        .await
        .inspect_err(|_| audit_failure(request, &memory.id, &memory.namespace))
    }

    #[allow(clippy::too_many_arguments)]
    async fn store_supersession_attempt(
        &self,
        ctx: &CallerContext,
        memory: &Memory,
        embedding: Option<&[f32]>,
        space: Option<&str>,
        request: SupersessionRequest<'_>,
        lock_key: &str,
    ) -> StoreResult<SupersessionResult> {
        gate_record_stop_cached(&self.record_stop)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("begin supersession", e))?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(lock_key)
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err("lock ruling key", e))?;
        let old = sqlx::query(
            "SELECT * FROM memories WHERE namespace = $1 AND metadata->'ruling_key' = $2 \
             ORDER BY created_at DESC, id DESC LIMIT 1 FOR UPDATE",
        )
        .bind(&memory.namespace)
        .bind(&memory.metadata[crate::models::field_names::RULING_KEY])
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| to_store_err("read ruling predecessor", e))?
        .as_ref()
        .map(Self::row_to_memory)
        .transpose()?;
        let id = self
            .store_with_embedding_in_tx(
                &mut tx,
                ctx,
                memory,
                embedding,
                space,
                crate::storage::InsertConflictArm::Refuse,
            )
            .await?;
        if id != memory.id {
            return Err(StoreError::IntegrityFailed {
                detail: "fresh supersession insert changed id".into(),
            });
        }
        let mut result = SupersessionResult {
            id,
            superseded: None,
            refusal: None,
        };
        if let Some(old) = old {
            let row = sqlx::query("SELECT * FROM memories WHERE id = $1 FOR UPDATE")
                .bind(&result.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| to_store_err("read ruling replacement", e))?;
            let new = Self::row_to_memory(&row)?;
            match authorize_supersession(
                request.principal,
                request.as_admin,
                &crate::identity::admin_agent_ids(),
                &old,
                &new,
            ) {
                SupersessionDecision::Authorized(authorized) => {
                    self.archive_as_superseded(&mut tx, &authorized).await?;
                    result.superseded = Some(old.id);
                }
                SupersessionDecision::Refused(reason) => result.refusal = Some(reason),
                SupersessionDecision::AlreadySuperseded => {}
            }
        }
        tx.commit()
            .await
            .map_err(|e| to_store_err("commit supersession", e))?;
        Ok(result)
    }

    /// CLI resolve's SAL twin; each retry rereads and reauthorizes both rows.
    pub(super) async fn resolve_supersession_pg(
        &self,
        old_id: &str,
        new_id: &str,
        request: SupersessionRequest<'_>,
    ) -> StoreResult<SupersessionResult> {
        self.resolve_supersession_bound(old_id, new_id, request, None)
            .await
    }

    /// #3587 propose mode: the pg twin of `storage::supersession::
    /// resolve_proposal` — the proposal must still bind both rows inside
    /// the same locked transaction.
    async fn resolve_supersession_bound(
        &self,
        old_id: &str,
        new_id: &str,
        request: SupersessionRequest<'_>,
        proposal: Option<&SupersessionProposal>,
    ) -> StoreResult<SupersessionResult> {
        async {
            self.gate_record_stop().await?;
            let mut retry = super::tx_retry::TxRetry::new("resolve supersession");
            let (result, new) = loop {
                match self
                    .resolve_supersession_attempt(old_id, new_id, request, proposal)
                    .await
                {
                    Ok(result) => break result,
                    Err(error) => retry.consider(error).await?,
                }
            };
            result.audit(request, &new);
            Ok(result)
        }
        .await
        .inspect_err(|_| audit_failure(request, new_id, ""))
    }

    async fn resolve_supersession_attempt(
        &self,
        old_id: &str,
        new_id: &str,
        request: SupersessionRequest<'_>,
        proposal: Option<&SupersessionProposal>,
    ) -> StoreResult<(SupersessionResult, Memory)> {
        gate_record_stop_cached(&self.record_stop)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("begin resolve", e))?;
        // CONCURRENCY-04: lock both live rows in id order, even when two callers
        // propose opposite winners. Archived replay is read only after live locks.
        let rows =
            sqlx::query("SELECT * FROM memories WHERE id = $1 OR id = $2 ORDER BY id FOR UPDATE")
                .bind(old_id)
                .bind(new_id)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| to_store_err("lock resolve rows", e))?;
        let memories = rows
            .iter()
            .map(Self::row_to_memory)
            .collect::<StoreResult<Vec<_>>>()?;
        let new = memories
            .iter()
            .find(|m| m.id == new_id)
            .ok_or_else(|| StoreError::NotFound { id: new_id.into() })?;
        let archived;
        let (old, old_is_archived) = match memories.iter().find(|m| m.id == old_id) {
            Some(old) => (old, false),
            None => {
                let row = sqlx::query("SELECT * FROM archived_memories WHERE id = $1 FOR UPDATE")
                    .bind(old_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| to_store_err("read resolve archive", e))?
                    .ok_or_else(|| StoreError::NotFound { id: old_id.into() })?;
                archived = Self::row_to_memory(&row)?;
                (&archived, true)
            }
        };
        let mut result = SupersessionResult {
            id: new.id.clone(),
            superseded: None,
            refusal: None,
        };
        match decide(old, new, old_is_archived, request, proposal) {
            Ok(Some(authorized)) => {
                self.archive_as_superseded(&mut tx, &authorized).await?;
                result.superseded = Some(old.id.clone());
            }
            Ok(None) => {}
            Err(reason) => result.refusal = Some(reason),
        }
        tx.commit()
            .await
            .map_err(|e| to_store_err("commit resolve", e))?;
        Ok((result, new.clone()))
    }

    /// #3587 propose mode: the pg twin of `supersession_pending::
    /// gate_before_approve` — read-only, no row locks, run before approving.
    pub(super) async fn supersession_gate_before_approve_pg(
        &self,
        ctx: &CallerContext,
        pending_id: &str,
        approver_id: &str,
        request: SupersessionRequest<'_>,
    ) -> StoreResult<ProposalGate> {
        use crate::store::MemoryStore as _;
        let Some(pa) = self.get_pending(ctx, pending_id).await? else {
            return Ok(ProposalGate::NotSupersession);
        };
        if !is_supersession(&pa) {
            return Ok(ProposalGate::NotSupersession);
        }
        let refusal = match proposal_of(&pa, Some(approver_id), request) {
            Ok(proposal) => {
                let (old, new, old_is_archived) = self.read_proposal_pair(&proposal).await?;
                decide(&old, &new, old_is_archived, request, Some(&proposal)).err()
            }
            Err(reason) => Some(reason),
        };
        Ok(match refusal {
            None => ProposalGate::Proceed,
            Some(reason) => {
                audit_refusal(request, &pa, reason);
                ProposalGate::Refused(reason)
            }
        })
    }

    async fn read_proposal_pair(
        &self,
        proposal: &SupersessionProposal,
    ) -> StoreResult<(Memory, Memory, bool)> {
        let fetch = |table: &'static str, id: &str| {
            let sql = format!("SELECT * FROM {table} WHERE id = $1");
            let id = id.to_owned();
            async move {
                sqlx::query(&sql)
                    .bind(id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| to_store_err("read supersession proposal row", e))?
                    .as_ref()
                    .map(Self::row_to_memory)
                    .transpose()
            }
        };
        let new = fetch("memories", proposal.new_id())
            .await?
            .ok_or_else(|| StoreError::NotFound {
                id: proposal.new_id().into(),
            })?;
        if let Some(old) = fetch("memories", proposal.old_id()).await? {
            return Ok((old, new, false));
        }
        let old = fetch("archived_memories", proposal.old_id())
            .await?
            .ok_or_else(|| StoreError::NotFound {
                id: proposal.old_id().into(),
            })?;
        Ok((old, new, true))
    }

    /// #3587 propose mode: execute an APPROVED pending row with the approve
    /// surface's hardened principal (pg twin of `supersession_pending::
    /// execute_with`).
    pub(super) async fn execute_pending_action_with_pg(
        &self,
        ctx: &CallerContext,
        pending_id: &str,
        request: SupersessionRequest<'_>,
    ) -> StoreResult<Option<String>> {
        use crate::store::MemoryStore as _;
        let pa = match self.get_pending(ctx, pending_id).await? {
            Some(pa) if is_supersession(&pa) => pa,
            _ => return self.execute_pending_action(ctx, pending_id).await,
        };
        self.gate_record_stop().await?;
        if pa.status != "approved" {
            return Err(StoreError::InvalidInput {
                detail: format!("cannot execute non-approved action (status={})", pa.status),
            });
        }
        let refused = |reason: crate::identity::supersession::SupersessionRefusal| {
            StoreError::PermissionDenied {
                action: crate::store::EXECUTE_PENDING_ACTION.to_string(),
                target: pending_id.to_string(),
                reason: reason.to_string(),
            }
        };
        if let Err(e) = crate::storage::verify_payload_agent_id(&pa) {
            self.emit_pending_event_best_effort(
                &pa,
                crate::storage::EVENT_PENDING_ACTION_REFUSED_AGENT_ID_MISMATCH,
                None,
            )
            .await;
            return Err(StoreError::PermissionDenied {
                action: crate::store::EXECUTE_PENDING_ACTION.to_string(),
                target: pending_id.to_string(),
                reason: e.to_string(),
            });
        }
        let proposal = match proposal_of(&pa, pa.decided_by.as_deref(), request) {
            Ok(proposal) => proposal,
            Err(reason) => {
                audit_refusal(request, &pa, reason);
                self.emit_pending_event_best_effort(
                    &pa,
                    crate::storage::supersession_pending::EVENT_REFUSED_SUPERSESSION,
                    None,
                )
                .await;
                return Err(refused(reason));
            }
        };
        let result = self
            .resolve_supersession_bound(
                proposal.old_id(),
                proposal.new_id(),
                request,
                Some(&proposal),
            )
            .await?;
        if let Some(reason) = result.refusal {
            self.emit_pending_event_best_effort(
                &pa,
                crate::storage::supersession_pending::EVENT_REFUSED_SUPERSESSION,
                None,
            )
            .await;
            return Err(refused(reason));
        }
        self.emit_pending_event_best_effort(
            &pa,
            crate::storage::EVENT_PENDING_ACTION_APPROVED,
            pa.decided_by.as_deref(),
        )
        .await;
        Ok(Some(result.id))
    }

    /// Best-effort pending-action audit append (the governance decision or
    /// refusal stands even if the chain append fails — the #3180 posture).
    async fn emit_pending_event_best_effort(
        &self,
        pa: &crate::models::PendingAction,
        event_type: &str,
        decided_by: Option<&str>,
    ) {
        if let Err(e) = self
            .pg_emit_pending_action_event(pa, event_type, decided_by)
            .await
        {
            tracing::warn!(pending_id = %pa.id, event_type, "pending-action audit append failed: {e}");
        }
    }

    async fn archive_as_superseded(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        authorized: &crate::identity::supersession::AuthorizedSupersession<'_>,
    ) -> StoreResult<()> {
        gate_record_stop_cached(&self.record_stop)?;
        let old = authorized.old();
        let new = authorized.new_memory();
        if old.id == new.id {
            return Err(StoreError::IntegrityFailed {
                detail: "supersession cannot archive replacement id".into(),
            });
        }
        let mut archive_ctx =
            CallerContext::for_agent(authorized.principal().agent_id().to_owned());
        // Only the hardened authority token can enable this explicit admin lane.
        archive_ctx.bypass_visibility = authorized.as_admin();
        let count = self
            .archive_by_ids_in_tx(
                tx,
                &archive_ctx,
                std::slice::from_ref(&old.id),
                crate::models::field_names::ARCHIVE_REASON_SUPERSEDED,
                chrono::Utc::now(),
            )
            .await?;
        if count != 1 {
            return Err(StoreError::IntegrityFailed {
                detail: "supersession archive lost predecessor".into(),
            });
        }
        let old_count = sqlx::query("UPDATE archived_memories SET metadata = jsonb_set(metadata, '{superseded_by}', to_jsonb($1::text)) WHERE id = $2")
            .bind(&new.id).bind(&old.id).execute(&mut **tx).await.map_err(|e| to_store_err("stamp archive pointer", e))?.rows_affected();
        let new_count = sqlx::query("UPDATE memories SET metadata = jsonb_set(metadata, '{superseded_id}', to_jsonb($1::text)) WHERE id = $2")
            .bind(&old.id).bind(&new.id).execute(&mut **tx).await.map_err(|e| to_store_err("stamp replacement pointer", e))?.rows_affected();
        if old_count != 1 || new_count != 1 {
            return Err(StoreError::IntegrityFailed {
                detail: "supersession pointer row missing".into(),
            });
        }
        Ok(())
    }
}
