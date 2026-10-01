// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4023 — the postgres federation same-`id` merge body, moved out of
//! `src/store/postgres.rs` (at its `qual_10_module_size_ceiling` budget; no
//! ceiling raise) per the 5-agent vote (4d3ea1c5), memory 179cf088. The trait
//! arms in `postgres.rs` forward here.
//!
//! NOTE for lane-A assembly with #4029-#4033: the resurrection-guard probe
//! below still runs on the POOL before the transaction (the pre-#4029 shape).
//! The assembled body must instead take #4029's in-transaction
//! `admit_or_tombstoned` + stripe advisory lock, with lock order: stripe
//! advisory lock -> row `FOR UPDATE` -> authorizer.
//!
//! NOTE for #4216/#4218 (PR #4348): it edits the pg `merge_inbound` body in
//! `postgres.rs`. That body MOVED here, so git will show a conflict on deleted
//! lines; its hunks must be PORTED into this file, not re-applied to
//! `postgres.rs`. Its `read_slot_preimage` `FOR UPDATE` goes AFTER #4029's
//! `admit_or_tombstoned` stripe lock (stripe -> row `FOR UPDATE` ->
//! authorizer, CONCURRENCY-04).

use super::*;

impl PostgresStore {
    /// Shared body of [`MemoryStore::merge_inbound`] and (#4023)
    /// [`MemoryStore::merge_inbound_authorized`]: `authorize_stored` is `None`
    /// for the unchecked legacy entry and `Some` for the federation receive
    /// funnel's in-transaction peer-scope re-check.
    pub(super) async fn pg_merge_inbound(
        &self,
        ctx: &CallerContext,
        inbound: &Memory,
        receiver_verified: bool,
        authorize_stored: Option<crate::storage::StoredNamespaceAuthorizer<'_>>,
    ) -> StoreResult<String> {
        self.gate_record_stop().await?;
        // v0.8.1 W2.3 (#1821 / gap G30) — resurrection guard (postgres parity
        // with the sqlite insert_if_newer gate). DROP an inbound write for a
        // tombstoned id (tombstone-wins) so a peer cannot revive a forgotten
        // row via LWW.
        let tombstoned: bool = sqlx::query_scalar(federation_3075::SQL_FORGET_TOMBSTONE_EXISTS)
            .bind(&inbound.id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| to_store_err("merge_inbound tombstone check", e))?;
        if tombstoned {
            tracing::info!(
                target: crate::storage::FORGET_TOMBSTONE_TRACE_TARGET,
                memory_id = %inbound.id,
                "{}",
                crate::storage::FORGET_TOMBSTONE_DROP_MSG
            );
            return Ok(inbound.id.clone());
        }

        // v0.8.1 W1 (#1821 / gap G29) — credential REDACT on the postgres
        // federation RECEIVE funnel (parity with sqlite insert_if_newer).
        // ALWAYS redact, NEVER refuse — a rejected inbound row would diverge
        // replicas. No-op unless screening was seeded non-`off`.
        let screened = crate::secret_screen::redact_memory_for_receive(inbound);
        let inbound = screened.as_ref().unwrap_or(inbound);
        // ARCH-1 parity (mirrors apply_remote_memory) — a federation-
        // pushed row must clear the same pre-write governance hook as a
        // locally-authored write.
        consult_governance_pre_write_pg(inbound)?;
        // #2059/#2102 — TRACT covenant clause 1 on the federation-RECEIVE
        // merge funnel. Advisory-only (never refuses), CRDT-safe.
        crate::storage::consult_why_trace_gate_inbound(inbound);

        // v0.8.0 Pillar-3 (#1709 / #224) — read the existing row BY id
        // (bypassing the scope=private visibility gate: this is the
        // federation reconciliation path, not a tenant-facing read; the
        // federation allowlist + peer-attestation gate enforce
        // cross-tenant isolation upstream), merge field-wise via the SAME
        // pure `crate::models::merge_memory` Rust reconciler the sqlite
        // path uses (no per-adapter merge SQL → no merge drift), then
        // persist the full merged row by id inside a transaction. If no
        // row matches by id, fall through to `apply_remote_memory` (the
        // postgres `insert_if_newer` twin) for the fresh-insert +
        // (title, namespace) dedup-upsert LWW path.
        //
        // f1 goal4 FA (#3266, GOD ruling): the read and the write share ONE
        // transaction. The row is read `FOR UPDATE` inside it and the lock is
        // held to commit, so the merge (and its local-wins lifecycle predicate)
        // is computed from the row actually being overwritten — a local rewind
        // or release that commits while this peer write is in flight is either
        // seen here or waits for it; never undone from a stale snapshot.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("merge_inbound begin tx", e))?;
        let existing_row = sqlx::query(&SQL_SELECT_MEMORY_ROW_BY_ID_FOR_UPDATE)
            .bind(&inbound.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| to_store_err("merge_inbound select by id", e))?;

        let Some(row) = existing_row else {
            // No row by this id — defer to the unchanged LWW path (the empty
            // transaction is rolled back on drop).
            drop(tx);
            return self.apply_remote_memory(ctx, inbound).await;
        };

        let existing = Self::row_to_memory(&row)?;
        // #4023 — re-authorize the peer's scope against the row actually being
        // overwritten, read `FOR UPDATE` under this transaction: the funnel's
        // scope gate ran on an earlier pool read, and `merge_memory` LWWs
        // `namespace`, so a row a broader writer moved in between must not
        // take this peer's write. Refusal drops (rolls back) the transaction.
        if let Some(authorize) = authorize_stored
            && !authorize(&existing.namespace)
        {
            drop(tx);
            return Err(StoreError::PermissionDenied {
                action: crate::store::FEDERATION_MERGE_INBOUND.to_string(),
                target: inbound.id.clone(),
                reason: crate::storage::inbound_stored_namespace_refused(
                    &inbound.id,
                    &existing.namespace,
                ),
            });
        }
        // #1719 item 3a — neutralize the untrusted inbound's self-asserted
        // `metadata.attest_level` to `claimed` before merge (identical to
        // the sqlite `db::merge_inbound` boundary, no per-backend drift) so
        // a forged peer cannot win the attested-identity LWW tiebreak by
        // self-asserting a verified level.
        let sanitized = crate::models::sanitize_inbound_attestation(inbound);
        // #1755 item 3b — cap a relayed row's post-dated `updated_at` (the
        // primary LWW key) to a freshness ceiling (identical to the sqlite
        // `db::merge_inbound` boundary, no per-backend drift) so an enrolled
        // relay cannot win the merge by stamping a far-future timestamp.
        let prepared = crate::models::clamp_inbound_updated_at(
            sanitized,
            &chrono::Utc::now().to_rfc3339(),
            crate::identity::attest::ATTEST_CREATED_AT_SKEW_SECS,
        );
        let merged = crate::models::merge_memory(&existing, &prepared);
        // #2863 — atomic `agent_attested` re-assert (postgres twin of the sqlite
        // `db::merge_inbound` path): `sanitize` above demoted the inbound level
        // to `claimed` for the LWW tiebreak, but that must not DEMOTE a level
        // THIS node verified over the persisted bytes. When the merged row's full
        // SignableWrite surface + `write_signature` is byte-identical to the
        // (post-redaction) verified `inbound`, restore `agent_attested`. The
        // restored level flows into the `metadata` column encoded below, so it is
        // written in the SAME UPDATE (atomic, no crash window). No-op when
        // `receiver_verified` is false.
        let merged =
            crate::models::reassert_verified_attestation(merged, inbound, receiver_verified);

        // Encode the JSON-shaped columns the same way the
        // `apply_remote_memory` insert path does.
        let created_at = parse_rfc3339_required(&merged.created_at)?;
        let updated_at = parse_rfc3339_required(&merged.updated_at)?;
        let last_accessed_at = parse_rfc3339_opt(merged.last_accessed_at.as_deref());
        let expires_at = parse_rfc3339_opt(merged.effective_expires_at().as_deref());
        let tags_json =
            serde_json::to_value(&merged.tags).map_err(|e| StoreError::IntegrityFailed {
                detail: serialize_err("tags", e),
            })?;
        let citations_json =
            serde_json::to_string(&merged.citations).map_err(|e| StoreError::IntegrityFailed {
                detail: serialize_err("citations", e),
            })?;
        let source_span_json = match &merged.source_span {
            Some(span) => {
                Some(
                    serde_json::to_string(span).map_err(|e| StoreError::IntegrityFailed {
                        detail: serialize_err(COL_SOURCE_SPAN, e),
                    })?,
                )
            }
            None => None,
        };
        let confidence_signals_json = match &merged.confidence_signals {
            Some(s) => Some(
                serde_json::to_string(s).map_err(|e| StoreError::IntegrityFailed {
                    detail: serialize_err(COL_CONFIDENCE_SIGNALS, e),
                })?,
            ),
            None => None,
        };
        let confidence_decayed_at = parse_rfc3339_opt(merged.confidence_decayed_at.as_deref());
        let mentioned_entity_id = crate::storage::extract_mentioned_entity_id(&merged);
        // #2292 — at-rest content-seal on the same-id federation-MERGE funnel.
        // This funnel (found during the #2292 sweep; NOT in the issue's audit
        // list) rewrites an EXISTING row's `content = $5` with the merged
        // content but omitted `encrypted_envelope` from the SET — so under an
        // enabled gate a federation merge OVERWROTE a sealed row's content with
        // PLAINTEXT and left a STALE ciphertext envelope (desync + leak).
        // `merge_memory` already resolved every field, so the sealed content +
        // envelope are written verbatim (no CASE); mirrors the in-place
        // `update()` seal at ~4947.
        // Full-row UPDATE by id — every column is written verbatim from
        // the already-resolved merged row (NO CASE / GREATEST / COALESCE
        // re-application; `merge_memory` resolved every field), in the SAME
        // transaction that holds the row lock (f1 goal4 FA). The node-local
        // metadata keys are overlaid from the locked row by an atomic jsonb
        // merge (`pg_node_local_overlay`), never from a copy.
        // #3961 (the postgres half of #1773) — snapshot the PRE-MERGE row
        // before this peer-driven LWW full-row overwrite, in the SAME
        // transaction that holds the row lock, under
        // `archive_reason = 'federation_merge'`. Unconditional whenever a row
        // exists by id — exactly the sqlite `overwrite_full_row_by_id`
        // contract — so a merge where the remote wins the tiebreak leaves a
        // recoverable copy of the prior local content on BOTH backends
        // (`archive restore` / `undo-edit` have something to restore from).
        // DELETE + INSERT keeps the most-recent snapshot, the sqlite
        // `INSERT OR REPLACE` semantics, so a repeated merge is idempotent.
        sqlx::query(SQL_DELETE_ARCHIVED_MEMORY_BY_ID)
            .bind(&merged.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err("merge_inbound clear prior snapshot", e))?;
        sqlx::query(SQL_ARCHIVE_SNAPSHOT_LIVE_ROW)
            .bind(&merged.id)
            .bind(crate::models::field_names::ARCHIVE_REASON_FEDERATION_MERGE)
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err("merge_inbound pre-merge snapshot", e))?;
        let (merge_content, merge_envelope) = seal_content_for_insert(&mut *tx, &merged).await?;
        sqlx::query(&SQL_MERGE_INBOUND_FULL_ROW_UPDATE)
            .bind(&merged.id)
            .bind(merged.tier.as_str())
            .bind(&merged.namespace)
            .bind(&merged.title)
            // #2292 — sealed placeholder ("" under an enabled gate, else content).
            .bind(&merge_content)
            .bind(&tags_json)
            .bind(merged.priority)
            .bind(merged.confidence)
            .bind(&merged.source)
            .bind(merged.access_count)
            .bind(created_at)
            .bind(updated_at)
            .bind(last_accessed_at)
            .bind(expires_at)
            .bind(&merged.metadata)
            .bind(merged.reflection_depth)
            .bind(merged.memory_kind.as_str())
            .bind(&citations_json)
            .bind(merged.source_uri.as_ref())
            .bind(source_span_json.as_deref())
            .bind(merged.confidence_source.as_str())
            .bind(confidence_signals_json.as_deref())
            .bind(confidence_decayed_at)
            .bind(merged.entity_id.as_ref())
            .bind(merged.persona_version)
            .bind(merged.version)
            .bind(mentioned_entity_id.as_deref())
            .bind(merged.lifecycle_state.as_str())
            // #2207 — the #1834 claim-bitemporal VALID-time interval (TEXT
            // RFC3339). The same-`id` federation merge lane MUST persist the
            // merged `valid_until` so a peer that CLOSED a claim replicates the
            // close by id (newer-wins in `merge_memory`) → replicas converge on
            // VALID-time. `valid_from` is local-immutable in `merge_memory`; the
            // overwrite is a no-op (matches the `apply_remote_memory` upsert
            // arm's `valid_from = memories.valid_from` genesis-wins rule).
            // Canonicalized to the fixed UTC rendering (pre-ship 3x7).
            .bind(crate::validate::canonical_valid_time_opt(
                merged.valid_from.as_deref(),
            ))
            .bind(crate::validate::canonical_valid_time_opt(
                merged.valid_until.as_deref(),
            ))
            // #2292 — sealed ciphertext envelope ($31); NULL when encryption off.
            .bind(merge_envelope)
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err("merge_inbound full-row update", e))?;
        // APPEND-ONLY-SANCTIONED (#1823 G6) — COW SUPERSEDE: the federation
        // LWW full-row overwrite rewrites content in place (same id); the
        // pre-merge content lives in the `federation_merge` archive snapshot
        // taken above in this tx (#3961), never in the leaf.
        // Append ONE identity-only SUPERSEDE leaf in this tx.
        pg_emit_revision_leaf_if_enabled(
            &mut tx,
            &merged.id,
            crate::revisions::RecordKind::Supersede,
            None,
            &merged.namespace,
            merged.metadata.get("agent_id").and_then(|v| v.as_str()),
            &chrono::Utc::now().to_rfc3339(),
        )
        .await
        .map_err(|e| to_store_err(CTX_APPEND_SUPERSEDE_LEAF, e))?;
        tx.commit()
            .await
            .map_err(|e| to_store_err("merge_inbound commit tx", e))?;

        Ok(merged.id)
    }
}
