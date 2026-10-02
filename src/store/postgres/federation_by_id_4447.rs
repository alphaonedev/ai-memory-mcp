// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #4447 — the postgres federation by-id lanes (`deletions[]`,
//! `archives[]`, `restores[]`, `links[]`) with the in-transaction peer-scope
//! re-check, the sibling of the #4023 `pg_merge_inbound` fix.
//!
//! The four write bodies (`apply_remote_deletion`, the archive batch, the
//! archive restore, `apply_remote_link`) MOVED here verbatim from
//! `postgres.rs` (at its `qual_10_module_size_ceiling` budget; no ceiling
//! raise), each gaining one `authorize_stored: Option<..>` parameter and ONE
//! block that locks the target row inside the write transaction and refuses
//! with `PermissionDenied` when the verdict says the row left the peer's scope.
//! The deletions, archives and restores lanes lock `FOR UPDATE` (the first lock
//! the transaction takes on the row). The LINKS lane locks BOTH endpoints
//! `FOR SHARE`, one lock each in ascending id order through `lock_order_4209`:
//! `FOR UPDATE` deadlocks with a local link write, key-share-then-update
//! deadlocks two replays, and key-share alone would not hold a `namespace`
//! relocation off. `None` is the unchecked legacy entry (tests, operator lanes);
//! the trait `*_authorized` arms in `postgres.rs` pass `Some`. The `postgres.rs`
//! trait arms for the unchecked methods forward here with `None`.
//!
//! NOTE for lane-A assembly with #4029-#4033 / #4348 (which edit these bodies):
//! port their hunks into THIS file; the bodies no longer exist in `postgres.rs`.

use super::*;

/// The by-id live-row namespace read, `FOR UPDATE`: the lock the in-transaction
/// re-check holds to commit.
const SQL_NAMESPACE_BY_ID_FOR_UPDATE: &str =
    "SELECT namespace FROM memories WHERE id = $1 FOR UPDATE";

/// The archive-table twin for the `restores[]` lane.
const SQL_ARCHIVED_NAMESPACE_BY_ID_FOR_UPDATE: &str =
    "SELECT namespace FROM archived_memories WHERE id = $1 FOR UPDATE";

impl PostgresStore {
    pub(super) async fn apply_remote_link_inner(
        &self,
        _ctx: &CallerContext,
        link: &MemoryLink,
        attest_level: &str,
        authorize_stored: Option<crate::storage::ByIdNamespaceAuthorizer<'_>>,
    ) -> StoreResult<()> {
        self.gate_record_stop().await?;
        // Mirrors sqlite db::create_link_inbound. The unique
        // (source_id, target_id, relation) index makes duplicate
        // pushes a no-op (ON CONFLICT DO NOTHING), so retries and
        // peer-to-peer fanouts converge cleanly.
        let created_at = parse_rfc3339_required(&link.created_at)?;
        let valid_from = parse_rfc3339_opt(link.valid_from.as_deref());
        let valid_until = parse_rfc3339_opt(link.valid_until.as_deref());

        // v0.7.0.1 G4 — federation replay must keep the AGE
        // projection in sync with the SQL `memory_links` table the
        // same way the local-write path does. A single transaction
        // lets the SQL row + AGE MERGE commit atomically.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("begin apply_remote_link tx", e))?;
        // #4210 — the endpoint locks, taken ONCE in ascending id order. The
        // unchecked replay takes the foreign keys' `FOR KEY SHARE` (many
        // replays on a hot endpoint do not serialise). #4447 — the authorized
        // replay must additionally HOLD OFF a namespace relocation, which
        // `FOR KEY SHARE` does not (`namespace` is a non-key column), so it
        // takes `FOR SHARE` instead: one lock per endpoint, no second lock and
        // therefore no KEY SHARE -> UPDATE upgrade (two replays sharing an
        // endpoint would each wait on the other's key-share: 40P01). `FOR SHARE`
        // blocks an UPDATE yet stays compatible with other replays and with the
        // foreign keys' key-share locks, and the namespace is read under it.
        let ends = if authorize_stored.is_some() {
            lock_order_4209::replay_endpoint_share_locks(&link.source_id, &link.target_id)
        } else {
            lock_order_4209::replay_endpoint_locks(&link.source_id, &link.target_id)
        };
        lock_order_4209::lock_memories_in_id_order(&mut tx, &ends)
            .await
            .map_err(|e| to_store_err("lock apply_remote_link endpoints", e))?;
        // #4447 — re-authorize each endpoint's stored namespace under the lock
        // just taken (ascending id, one read per distinct endpoint); a row
        // absent under the lock is left to the foreign key on the INSERT below.
        if let Some(authorize) = authorize_stored {
            for (endpoint, _) in lock_order_4209::canonical_lock_plan(&ends) {
                let stored: Option<(String,)> =
                    sqlx::query_as("SELECT namespace FROM memories WHERE id = $1")
                        .bind(endpoint)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(|e| to_store_err("apply_remote_link authorize lookup", e))?;
                if let Some((stored_ns,)) = stored
                    && !authorize(endpoint, &stored_ns)
                {
                    drop(tx);
                    return Err(StoreError::PermissionDenied {
                        action: crate::store::FEDERATION_APPLY_LINK.to_string(),
                        target: endpoint.to_string(),
                        reason: crate::storage::inbound_by_id_namespace_refused(
                            crate::federation::receive_auth::LANE_LINKS,
                            endpoint,
                            &stored_ns,
                        ),
                    });
                }
            }
        }

        sqlx::query(
            "INSERT INTO memory_links (
                source_id, target_id, relation, created_at,
                valid_from, valid_until, observed_by, signature, attest_level
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (source_id, target_id, relation) DO NOTHING",
        )
        .bind(&link.source_id)
        .bind(&link.target_id)
        .bind(link.relation.as_str())
        .bind(created_at)
        .bind(valid_from)
        .bind(valid_until)
        .bind(link.observed_by.as_ref())
        .bind(link.signature.as_ref())
        .bind(attest_level)
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err("apply_remote_link", e))?;

        if matches!(self.kg_backend, KgBackend::Age) {
            // #1542 — same SAVEPOINT isolation + warn-on-runtime-failure
            // semantics as `link_internal`. Pre-#1542 this site
            // propagated the projection error with `?` AFTER the
            // relational INSERT had been queued in the tx, so a
            // fleet-wide `LOAD 'age'` refusal made every federated
            // link replay fail forever (DLQ churn) even though the
            // canonical row could have landed. The relational
            // `memory_links` row is the source of truth; the AGE
            // mirror degrades to the CTE fallback.
            sqlx::query("SAVEPOINT age_link_projection")
                .execute(&mut *tx)
                .await
                .map_err(|e| to_store_err("savepoint age_link_projection", e))?;
            // #2377 (FIX #9) — a federation relay of an already-invalidated
            // edge carries `valid_until`; project it onto the AGE edge so the
            // receiver's current-view Cypher reads exclude it exactly as the
            // relational reads do (else the relayed retraction is lost graph-side).
            let vf_str = valid_from.map(|t| t.to_rfc3339());
            let vu_str = valid_until.map(|t| t.to_rfc3339());
            match project_link_into_age(
                &mut tx,
                &link.source_id,
                &link.target_id,
                link.relation.as_str(),
                vf_str.as_deref(),
                vu_str.as_deref(),
            )
            .await
            {
                Ok(()) => {
                    sqlx::query("RELEASE SAVEPOINT age_link_projection")
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| to_store_err("release savepoint age_link_projection", e))?;
                }
                Err(e) if is_age_runtime_failure(&e) => {
                    sqlx::query("ROLLBACK TO SAVEPOINT age_link_projection")
                        .execute(&mut *tx)
                        .await
                        .map_err(|e2| to_store_err("rollback savepoint age_link_projection", e2))?;
                    // #3883 (A1) — was WARN-only; now RECORD the unreconciled
                    // projection (orphan => quarantined, transient => pending) so
                    // a federated relay's committed edge is not silently dropped
                    // from AGE forever.
                    record_failed_age_projection(
                        &mut tx,
                        "apply_remote_link",
                        &link.source_id,
                        &link.target_id,
                        link.relation.as_str(),
                        &e,
                    )
                    .await?;
                }
                Err(e) => return Err(e),
            }
        }

        tx.commit()
            .await
            .map_err(|e| to_store_err("commit apply_remote_link tx", e))?;
        Ok(())
    }

    pub(super) async fn apply_remote_deletion_inner(
        &self,
        id: &str,
        authorize_stored: Option<crate::storage::ByIdNamespaceAuthorizer<'_>>,
    ) -> StoreResult<bool> {
        self.gate_record_stop().await?;
        // #2493 / #2503 / #3192 — this override still does NOT compose
        // `self.delete` (that path carries the caller-owns gate this
        // inbound lane must not apply — `_ctx` is discarded). It DOES
        // share `pg_hard_delete_in_tx` with `delete` so the federated
        // `deletions[]` lane cannot again omit namespace-meta SEVER
        // (#2493) or the forget-tombstone + crypto-erase (#3192).
        //
        // Namespace-meta SEVER runs inside the tx even when the row is
        // already gone: a push naming an id with no local row must still
        // leave `namespace_meta` coherent rather than depending on
        // presence. A missing row writes no forget-tombstone (no
        // namespace to bind); that is a first-arrival hole, not a
        // resurrection of a locally-erased row — documented on the
        // sqlite twin.
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("apply_remote_deletion begin tx", e))?;
        // #4447 — re-authorize the peer's scope against the row actually being
        // changed, read `FOR UPDATE` under THIS transaction: the funnel's scope gate
        // ran on an earlier pool read and a broader writer can have moved the row
        // out of the peer's scope since. Refusal rolls the transaction back.
        if let Some(authorize) = authorize_stored {
            let stored: Option<(String,)> = sqlx::query_as(SQL_NAMESPACE_BY_ID_FOR_UPDATE)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| to_store_err("apply_remote_deletion authorize lookup", e))?;
            if let Some((stored_ns,)) = stored
                && !authorize(id, &stored_ns)
            {
                drop(tx);
                return Err(StoreError::PermissionDenied {
                    action: crate::store::FEDERATION_APPLY_DELETION.to_string(),
                    target: (id).to_string(),
                    reason: crate::storage::inbound_by_id_namespace_refused(
                        crate::federation::receive_auth::LANE_DELETIONS,
                        id,
                        &stored_ns,
                    ),
                });
            }
        }
        let rows = pg_hard_delete_in_tx(&mut tx, id)
            .await
            .map_err(|e| to_store_err("apply_remote_deletion", e))?;
        tx.commit()
            .await
            .map_err(|e| to_store_err("apply_remote_deletion commit tx", e))?;
        if rows > 0 {
            self.unproject_memory_ids_best_effort(&[id]).await;
        }
        Ok(rows > 0)
    }

    pub(super) async fn archive_by_ids_inner(
        &self,
        ctx: &CallerContext,
        ids: &[String],
        reason: Option<&str>,
        authorize_stored: Option<crate::storage::ByIdNamespaceAuthorizer<'_>>,
    ) -> StoreResult<usize> {
        self.gate_record_stop().await?;
        if ids.is_empty() {
            return Ok(0);
        }
        let now = chrono::Utc::now();
        // Parity finding #1 (2026-08) — the reason-less default was
        // `"manual"` here while BOTH sqlite funnels
        // (`storage::archive_memory_no_tx` / `archive_memory_for_caller`)
        // stamped `"archive"`, so the SAME reason-less archive produced a
        // DIFFERENT audit-trail value per backend and every reason-filtered
        // query / `archive_stats` report disagreed across backends. All
        // three funnels now read ONE shared SSOT const; `"archive"` is the
        // value pinned by the long-standing sqlite unit test
        // `archive_memory_default_reason_is_archive`.
        let archive_reason = reason.unwrap_or(crate::models::field_names::ARCHIVE_REASON_DEFAULT);
        // v1.0.0 #3520 — routed through the shared bounded-retry funnel: the
        // explicit-archive twin of `forget` / `run_gc`, holding the same
        // multi-relation lock set a concurrent bootstrap's
        // `CREATE INDEX IF NOT EXISTS` deadlocks against. `moved` is declared
        // INSIDE the block on purpose — it was an accumulator outside the
        // transaction, and a retry would have double-counted rows the rolled-back
        // attempt never archived. `now` / `archive_reason` stay outside so every
        // attempt stamps identically.
        let mut retry = tx_retry::TxRetry::new("archive_by_ids tx");
        let moved_count: usize = loop {
            let attempt: StoreResult<usize> = async {
                let mut tx = self
                    .pool
                    .begin()
                    .await
                    .map_err(|e| to_store_err("begin archive_by_ids tx", e))?;
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
                        &mut *tx,
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
                    // #4447 — re-authorize the peer's scope against the row actually being
                    // changed, read `FOR UPDATE` under THIS transaction: the funnel's scope gate
                    // ran on an earlier pool read and a broader writer can have moved the row
                    // out of the peer's scope since. Refusal rolls the transaction back.
                    if let Some(authorize) = authorize_stored {
                        let stored: Option<(String,)> = sqlx::query_as(SQL_NAMESPACE_BY_ID_FOR_UPDATE)
                            .bind(id)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(|e| to_store_err("archive_by_ids authorize lookup", e))?;
                        if let Some((stored_ns,)) = stored
                            && !authorize(id, &stored_ns)
                        {
                            return Err(StoreError::PermissionDenied {
                                action: crate::store::FEDERATION_APPLY_ARCHIVE.to_string(),
                                target: (id).to_string(),
                                reason: crate::storage::inbound_by_id_namespace_refused(
                                    crate::federation::receive_auth::LANE_ARCHIVES,
                                    id,
                                    &stored_ns,
                                ),
                            });
                        }
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
                    .execute(&mut *tx)
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
                    crate::store::postgres_parity::archive_links_for_memory_in_tx(&mut tx, id).await?;
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
                    pg_sever_namespace_standards_in_tx(&mut tx, id)
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
                                .fetch_optional(&mut *tx)
                                .await
                                .map_err(|e| to_store_err("archive_by_ids read row for leaf", e))?
                    {
                        pg_emit_revision_leaf_if_enabled(
                            &mut tx,
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
                    .execute(&mut *tx)
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
                        unproject_memory_from_age(&mut tx, id).await?;
                    }
                    moved += 1;
                }

                tx.commit()
                    .await
                    .map_err(|e| to_store_err("archive_by_ids commit", e))?;
                Ok(moved)
            }
            .await;
            match attempt {
                Ok(v) => break v,
                Err(e) => retry.consider(e).await?,
            }
        };
        Ok(moved_count)
    }

    pub(super) async fn archive_restore_inner(
        &self,
        ctx: &CallerContext,
        id: &str,
        authorize_stored: Option<crate::storage::ByIdNamespaceAuthorizer<'_>>,
    ) -> StoreResult<bool> {
        self.gate_record_stop().await?;
        // v1.0.0 #3520 — routed through the shared bounded-retry funnel. Restore
        // is the archive family's inverse (archived-row read + live INSERT +
        // preserved-edge re-insert + archive DELETE), so it holds the same
        // multi-relation lock set that a concurrent bootstrap's
        // `CREATE INDEX IF NOT EXISTS` deadlocks against. An early `return`
        // inside the block exits THIS attempt with that verdict, which the loop
        // then yields unchanged — a not-found restore is still `Ok(false)`.
        let mut retry = tx_retry::TxRetry::new("archive_restore tx");
        let restored: bool = loop {
            let attempt: StoreResult<bool> = async {
                let mut tx = self
                    .pool
                    .begin()
                    .await
                    .map_err(|e| to_store_err("begin archive_restore tx", e))?;

                // v1.0.0 #3271 (SECURITY-high) — SAL-side caller-owns gate, the
                // archive-RESTORE sibling of the #3193 `archive_by_ids` gate. Pre-fix
                // this funnel discarded its `_ctx` and matched on `WHERE id = $1` with
                // NO owner predicate, so on a postgres-backed daemon ANY authenticated
                // tenant could `POST /api/v1/archive/{victim's id}/restore` and pull a
                // DIFFERENT tenant's deliberately-archived row back into the live set —
                // and the 200-vs-404 split was an enumeration oracle over other
                // tenants' archived ids (the sqlite twin has refused via
                // `db::restore_archived_for_caller` since #940; #3193 fixed only the
                // archive side of this class). The existence probe now carries the
                // three-way owner predicate (owner OR inbox-target), so a non-owner
                // sees the SAME `Ok(false)` a truly-absent id gives → the handler's
                // 404 `NOT_FOUND_IN_ARCHIVE`, no oracle. Admin/operator lanes
                // (`ctx.bypass_visibility`) round-trip regardless of ownership, exactly
                // as they do on update / delete / archive.
                //
                // #3124 — the ownership verdict is the ONE cross-backend predicate:
                // the probe reads the row's owner stamp (typed by `jsonb_typeof`, so a
                // malformed owner is never mistaken for a stamp OR for unstamped) and
                // decides in Rust — owner, inbox recipient of a STAMPED row, or an
                // UNSTAMPED row admitted by `AI_MEMORY_UNSTAMPED_MUTATION` (`warn`, the
                // pre-#3124 outcome, WARNs + counts; `refuse` refuses). A refusal is
                // the same `Ok(false)` an absent id gives — still no oracle.
                // `admit_unstamped_row` feeds the INSERT's defense-in-depth arm so the
                // write predicate and this verdict cannot disagree.
                let mut admit_unstamped_row = false;
                if ctx.bypass_visibility {
                    let exists: Option<(String,)> =
                        sqlx::query_as("SELECT id FROM archived_memories WHERE id = $1")
                            .bind(id)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(|e| to_store_err("archive_restore lookup", e))?;
                    if exists.is_none() {
                        return Ok(false);
                    }
                } else {
                    let probe: Option<(Option<String>, Option<String>, Option<String>)> =
                        sqlx::query_as(
                            "SELECT jsonb_typeof(metadata->'agent_id'), metadata->>'agent_id', \
                             metadata->>'target_agent_id' \
                             FROM archived_memories WHERE id = $1",
                        )
                        .bind(id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(|e| to_store_err("archive_restore owner lookup", e))?;
                    let Some((owner_type, owner, inbox)) = probe else {
                        return Ok(false);
                    };
                    let caller = ctx.effective_principal();
                    let stamp = crate::identity::owner_stamp::OwnerStamp::of_pg(
                        owner_type.as_deref(),
                        owner.as_deref(),
                    );
                    let admitted = if stamp.is_unstamped() {
                        admit_unstamped_row = crate::identity::owner_stamp::admit_unstamped(
                            crate::identity::owner_stamp::MutationSite::postgres(
                                crate::identity::owner_stamp::funnel::RESTORE,
                            ),
                            id,
                            caller,
                        );
                        admit_unstamped_row
                    } else {
                        stamp.is_owned_by(caller)
                            || inbox
                                .as_deref()
                                .is_some_and(|t| !t.is_empty() && t == caller)
                    };
                    if !admitted {
                        return Ok(false);
                    }
                }

                // #1848 reconciled to #1771 (5-agent vote 4d3ea1c5, option B): this is
                // the OPERATOR un-forget path, so NO tombstone gate here — an authorized
                // restore round-trips per #1771.
                //
                // #3075 — the ORIGINAL justification for that omission was "federation
                // /sync/push restores[] are sqlite-only per federation_signing_check.rs,
                // never PostgresStore". That premise is RETIRED: the postgres receiver
                // now applies `restores[]`. The omission stands anyway, on the #1771
                // reasoning alone — but the G30 gate the federated lane needs is no
                // longer absent, it MOVED: it lives on `apply_remote_restore`
                // (`postgres/federation_3075.rs`), which runs it BEFORE composing this
                // method. Do NOT "fix" the two by merging them: gating here would break
                // the documented operator un-forget capability on both backends.

                // #4447 — re-authorize the peer's scope against the row actually being
                // changed, read `FOR UPDATE` under THIS transaction: the funnel's scope gate
                // ran on an earlier pool read and a broader writer can have moved the row
                // out of the peer's scope since. Refusal rolls the transaction back.
                if let Some(authorize) = authorize_stored {
                    let stored: Option<(String,)> =
                        sqlx::query_as(SQL_ARCHIVED_NAMESPACE_BY_ID_FOR_UPDATE)
                            .bind(id)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(|e| to_store_err("archive_restore authorize lookup", e))?;
                    if let Some((stored_ns,)) = stored
                        && !authorize(id, &stored_ns)
                    {
                        return Err(StoreError::PermissionDenied {
                            action: crate::store::FEDERATION_APPLY_RESTORE.to_string(),
                            target: (id).to_string(),
                            reason: crate::storage::inbound_by_id_namespace_refused(
                                crate::federation::receive_auth::LANE_RESTORES,
                                id,
                                &stored_ns,
                            ),
                        });
                    }
                }

                // Reject if the id is already in active memories.
                let active: Option<(String,)> = sqlx::query_as(SQL_SELECT_MEMORY_ID_BY_ID)
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| to_store_err("archive_restore active lookup", e))?;
                if active.is_some() {
                    return Err(StoreError::Conflict { id: id.to_string() });
                }

                // FX-C5 — substrate governance pre-write hook parity. Restoring
                // an archived row mints a fresh live row via a raw INSERT...SELECT
                // that bypasses `PostgresStore::store(..)` (which is where ARCH-1
                // wired in the `consult_governance_pre_write_pg` adapter at
                // line 7001). Without this call, an operator's signed governance
                // rule could be bypassed by restoring a row whose `(title,
                // namespace)` would otherwise be refused on a direct write.
                // Load the archived row shaped as a `Memory` and fire the hook
                // BEFORE the INSERT lands.
                let candidate = Self::load_archived_as_memory_pg(&mut *tx, id).await?;
                // #3124 — an UNSTAMPED row the owner probe above already admitted
                // (and reported) is not re-decided here: re-running the policy would
                // WARN + count the same restore twice. Every other row is re-checked
                // against the loaded candidate (same row, same single predicate).
                if !ctx.bypass_visibility
                    && !admit_unstamped_row
                    && !crate::visibility::caller_owns_for_mutation(
                        &candidate,
                        ctx.effective_principal(),
                        true,
                        crate::identity::owner_stamp::MutationSite::postgres(
                            crate::identity::owner_stamp::funnel::RESTORE,
                        ),
                    )
                {
                    return Ok(false);
                }
                consult_governance_pre_write_pg(&candidate)?;
                // #2110/#2113 audit — TRACT covenant clause 1 on the archive-RESTORE
                // funnel. Advisory-only (never refuses): a legacy archived row that
                // predates the covenant must stay restorable even under
                // AI_MEMORY_REQUIRE_WHY_TRACE=1 (postgres parity with the sqlite
                // `restore_archived` inbound gate).
                crate::storage::consult_why_trace_gate_inbound(&candidate);

                // v0.9.0 G8 (#1825) — re-mint the row's genesis content-id from the
                // archived row's ORIGINAL identity + PLAINTEXT content (decrypting the
                // archived envelope when present, falling back to the stored content
                // on any decrypt error) so the restored live row carries the same
                // `b3:` address it held before archival. created_at / title /
                // namespace / kind are the ORIGINAL archived values (via `candidate`),
                // NOT NOW(). Mirrors the sqlite `restored_cid_stamp` path.
                let restored_cid = {
                    let agent_id = candidate
                        .metadata
                        .get("agent_id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let (raw_content, envelope): (String, Option<Vec<u8>>) = sqlx::query_as(
                        "SELECT content, encrypted_envelope FROM archived_memories WHERE id = $1",
                    )
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|e| to_store_err("archive_restore load plaintext for cid", e))?;
                    let plaintext = match envelope {
                        Some(env) => {
                            crate::encryption::open_content(&env, &agent_id).unwrap_or(raw_content)
                        }
                        None => raw_content,
                    };
                    crate::identity::cid::stamp_cid(
                        &agent_id,
                        &candidate.namespace,
                        &candidate.title,
                        candidate.memory_kind.as_str(),
                        &candidate.created_at,
                        &plaintext,
                    )
                };

                let now = chrono::Utc::now();
                // #1025 (CRITICAL, 2026-05-21) — full v0.7.0 column carry on
                // archive→restore. Pre-#1025 the SELECT pulled only 17 columns
                // from archived_memories, so the restored row landed in
                // memories with reflection_depth=0, memory_kind='observation'
                // (the live-table DEFAULT), citations=[], version=1, etc. —
                // silent loss of provenance + persona + confidence calibration.
                // Now copies all 26 v0.7.0 fields (with COALESCE defaults for
                // pre-#1025 archived rows where the columns are NULL).
                sqlx::query(
                    "INSERT INTO memories (
                        id, tier, namespace, title, content, tags, priority, confidence,
                        source, access_count, created_at, updated_at, last_accessed_at,
                        expires_at, metadata, embedding, embedding_dim, embedding_space,
                        reflection_depth, atomised_into, atom_of, memory_kind,
                        entity_id, persona_version, citations, source_uri, source_span,
                        confidence_source, confidence_signals, confidence_decayed_at,
                        mentioned_entity_id, version, lifecycle_state, encrypted_envelope,
                        cid, cid_genesis, kind_provenance, valid_from, valid_until
                    )
                    SELECT id, COALESCE(original_tier, 'long'), namespace, title, content,
                           tags, priority, confidence, source, access_count, created_at,
                           $1::timestamptz, last_accessed_at, original_expires_at, metadata,
                           -- v1.0.0 #2167 (S8) restore/migrate HEAL (postgres twin):
                           -- keep the archived vector ONLY when its space matches the
                           -- live active space ($5); a foreign- or NULL-space vector
                           -- has its whole trio NULLed so the boot backfill re-embeds
                           -- from the durable text under the LIVE space (self-heal).
                           -- $5 NULL (no active embedder in this process) keeps any
                           -- STAMPED vector but still drops an unverifiable NULL one.
                           CASE WHEN embedding_space IS NOT NULL
                                     AND ($5::text IS NULL OR embedding_space = $5)
                                THEN embedding ELSE NULL END,
                           CASE WHEN embedding_space IS NOT NULL
                                     AND ($5::text IS NULL OR embedding_space = $5)
                                THEN embedding_dim ELSE NULL END,
                           CASE WHEN embedding_space IS NOT NULL
                                     AND ($5::text IS NULL OR embedding_space = $5)
                                THEN embedding_space ELSE NULL END,
                           COALESCE(reflection_depth, 0),
                           atomised_into,
                           atom_of,
                           COALESCE(memory_kind, 'observation'),
                           entity_id, persona_version,
                           COALESCE(citations, '[]'),
                           source_uri, source_span,
                           COALESCE(confidence_source, 'caller_provided'),
                           confidence_signals, confidence_decayed_at,
                           mentioned_entity_id,
                           COALESCE(version, 1),
                           COALESCE(lifecycle_state, 'open'),
                           encrypted_envelope,
                           -- v1.0.0 #2385 — the STORED genesis identity WINS. Pre-#2385
                           -- `archived_memories` had no cid columns, so restore
                           -- unconditionally bound the re-mint ($3/$4) recomputed from six
                           -- reconstructed inputs (agent_id / namespace / title / kind /
                           -- created_at / decrypted plaintext) — and a decrypt failure
                           -- there falls back to the CIPHERTEXT placeholder. Any drift
                           -- silently re-addressed the durable row and dangled every
                           -- `memory_links.source_cid` / `target_cid` mirror. The v90
                           -- columns make the identity a CARRIED fact; the re-mint is now
                           -- the legacy fallback for pre-v90 archive rows only.
                           -- The PAIR is selected atomically (the #2395 lesson applied
                           -- here): `cid_genesis` is the canonical PRE-IMAGE of `cid`, so
                           -- mixing a carried address with a re-derived pre-image would
                           -- produce a row whose own verify disagrees with itself.
                           CASE WHEN cid IS NOT NULL THEN cid ELSE $3::text END,
                           CASE WHEN cid IS NOT NULL THEN cid_genesis ELSE $4::bytea END,
                           -- v1.0.0 #2333 (FBL-03 pg mirror) — carry kind_provenance
                           -- back on restore; legacy pre-v87 archive rows re-derive
                           -- it from the metadata carrier, vocab-guarded (sqlite twin).
                           COALESCE(kind_provenance,
                                    CASE WHEN metadata->>'kind_provenance' IN
                                              ('declared','channel_derived','regex','llm')
                                         THEN metadata->>'kind_provenance' END),
                           valid_from, valid_until
                    FROM archived_memories WHERE id = $2
                      -- v1.0.0 #3271 — owner-predicated write (defense-in-depth with
                      -- the owner probe above; same predicate). $6 bypass
                      -- short-circuits the owner/inbox/legacy arms so operator lanes
                      -- still round-trip any row. #3124: owner equality is typed
                      -- (a malformed non-string owner never matches), the inbox arm
                      -- needs a STAMPED row, and the unstamped arm is live only when
                      -- the probe's `AI_MEMORY_UNSTAMPED_MUTATION` verdict admitted
                      -- it ($8) — the same ONE predicate as the sqlite
                      -- `db::restore_archived_for_caller`.
                      AND ($6::bool
                           OR (jsonb_typeof(metadata->'agent_id') = 'string'
                               AND metadata->>'agent_id' = $7)
                           OR (metadata->>'target_agent_id' = $7
                               AND metadata->>'agent_id' IS NOT NULL
                               AND metadata->>'agent_id' <> '')
                           OR ($8::bool
                               AND (metadata->>'agent_id' IS NULL
                                    OR metadata->>'agent_id' = '')))",
                )
                .bind(now)
                .bind(id)
                .bind(&restored_cid.cid)
                .bind(&restored_cid.genesis)
                // v1.0.0 #2167 (S8) — $5: the process-wide active-space fp (NULL when
                // this process resolved no embedder) driving the restore heal above.
                .bind(crate::embeddings::active_embedding_space())
                .bind(ctx.bypass_visibility)
                .bind(ctx.effective_principal())
                // #3124 — $8: the probe's unstamped-row verdict.
                .bind(admit_unstamped_row)
                .execute(&mut *tx)
                .await
                .map_err(|e| to_store_err("archive_restore insert", e))?;

                // #1771 (5-agent vote 4d3ea1c5) — re-insert this memory's preserved
                // `archived_memory_links` edges back into `memory_links`, AFTER the
                // memory row is restored above and within the same tx. Only edges
                // whose BOTH endpoints currently exist in `memories` are restored —
                // `memory_links` carries an `ON DELETE CASCADE` FK on both
                // endpoints, so an edge whose OTHER endpoint is permanently gone
                // would be rejected (and is correctly skipped here). Idempotent via
                // the PK `ON CONFLICT`. Postgres twin of the SQLite
                // `restore_links_for_memory` re-insert.
                // #2315 — RETURNING the actually-restored edges so they can be
                // re-projected into the AGE graph below (only edges this INSERT
                // landed; ON CONFLICT skips report nothing, which is correct —
                // an already-present edge is already projected or queued).
                // #2377 (FIX #9) — RETURNING carries `valid_from`/`valid_until` too so a
                // restored already-invalidated edge re-projects into AGE ALREADY-carrying
                // its validity (else the current-view Cypher reads would serve it as VALID).
                // #4210 sibling — the INSERT below key-shares every other endpoint
                // through the FK in plan order; take those locks first, ascending.
                sqlx::query(lock_order_4209::SQL_KEY_SHARE_ARCHIVED_LINK_PEERS)
                    .bind(id)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(|e| to_store_err("archive_restore lock link peers", e))?;
                let restored_edges: Vec<(
                    String,
                    String,
                    String,
                    Option<DateTime<Utc>>,
                    Option<DateTime<Utc>>,
                )> = sqlx::query_as(
                    "INSERT INTO memory_links (
                         source_id, target_id, relation, created_at, valid_from,
                         valid_until, observed_by, signature, attest_level,
                         source_cid, target_cid
                     )
                     SELECT aml.source_id, aml.target_id, aml.relation, aml.created_at,
                            aml.valid_from, aml.valid_until, aml.observed_by,
                            aml.signature, aml.attest_level,
                            aml.source_cid, aml.target_cid
                     FROM archived_memory_links aml
                     WHERE (aml.source_id = $1 OR aml.target_id = $1)
                       AND EXISTS (SELECT 1 FROM memories m WHERE m.id = aml.source_id)
                       AND EXISTS (SELECT 1 FROM memories m WHERE m.id = aml.target_id)
                     ON CONFLICT (source_id, target_id, relation) DO NOTHING
                     RETURNING source_id, target_id, relation, valid_from, valid_until",
                )
                .bind(id)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| to_store_err("archive_restore restore links", e))?;

                // #2315 — re-PROJECT the restored edges into the AGE `memory_graph`.
                // Every delete path unprojects (forget / delete / consolidate / gc /
                // size_gc / archive_by_ids), but restore previously re-inserted the
                // relational rows WITHOUT re-projecting, so an AGE-routed kg_query
                // permanently missed restored edges (the CTE fallback fires only on
                // AGE runtime failure, never on a valid-but-empty result) — a
                // split-brain with no self-heal. Deferred mode enqueues the outbox
                // rows in THIS tx (the drainer's existence re-check tolerates any
                // later delete); sync mode MERGEs via a SAVEPOINT so an AGE runtime
                // failure degrades to a WARN instead of failing the relational
                // restore (#700/#1542 posture — the graph is derived data; the
                // restore of the durable rows must never be blocked by it).
                if matches!(self.kg_backend, KgBackend::Age) {
                    for (src, dst, rel, valid_from, valid_until) in &restored_edges {
                        if matches!(
                            crate::config::age_projection_mode(),
                            crate::config::AgeProjectionMode::Deferred
                        ) {
                            // Deferred: the drainer re-reads validity from memory_links
                            // (#2377 FIX #9) at drain time, so no validity is threaded here.
                            sqlx::query(
                                "INSERT INTO kg_projection_outbox (source_id, target_id, relation) \
                                 VALUES ($1, $2, $3)",
                            )
                            .bind(src)
                            .bind(dst)
                            .bind(rel)
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| {
                                to_store_err("archive_restore enqueue kg_projection_outbox", e)
                            })?;
                        } else {
                            sqlx::query("SAVEPOINT age_restore_projection")
                                .execute(&mut *tx)
                                .await
                                .map_err(|e| to_store_err("savepoint age_restore_projection", e))?;
                            // #2377 (FIX #9) — carry the restored edge's validity.
                            let vf_str = valid_from.map(|t| t.to_rfc3339());
                            let vu_str = valid_until.map(|t| t.to_rfc3339());
                            match project_link_into_age(
                                &mut tx,
                                src,
                                dst,
                                rel,
                                vf_str.as_deref(),
                                vu_str.as_deref(),
                            )
                            .await
                            {
                                Ok(()) => {
                                    sqlx::query("RELEASE SAVEPOINT age_restore_projection")
                                        .execute(&mut *tx)
                                        .await
                                        .map_err(|e| {
                                            to_store_err(
                                                "release savepoint age_restore_projection",
                                                e,
                                            )
                                        })?;
                                }
                                Err(e) if is_age_runtime_failure(&e) => {
                                    sqlx::query("ROLLBACK TO SAVEPOINT age_restore_projection")
                                        .execute(&mut *tx)
                                        .await
                                        .map_err(|e2| {
                                            to_store_err(
                                                "rollback savepoint age_restore_projection",
                                                e2,
                                            )
                                        })?;
                                    // #3883 (A1) — was WARN-only; now RECORD.
                                    record_failed_age_projection(
                                        &mut tx,
                                        "archive_restore",
                                        src,
                                        dst,
                                        rel,
                                        &e,
                                    )
                                    .await?;
                                }
                                Err(e) => return Err(e),
                            }
                        }
                    }
                }

                sqlx::query(SQL_DELETE_ARCHIVED_MEMORY_BY_ID)
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| to_store_err("archive_restore delete", e))?;

                tx.commit()
                    .await
                    .map_err(|e| to_store_err("archive_restore commit", e))?;
                Ok(true)
            }
            .await;
            match attempt {
                Ok(v) => break v,
                Err(e) => retry.consider(e).await?,
            }
        };

        Ok(restored)
    }
}
