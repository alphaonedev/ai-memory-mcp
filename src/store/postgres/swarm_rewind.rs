// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 Boids predator plan item 3 (#3266 / #3922, 5-agent vote `4d3ea1c5`) —
//! the postgres twin of [`crate::storage::swarm_rewind`]: contaminate a
//! cascade root and its bounded `derives_from` descendants, freeze the
//! operator-named routines, and append ONE signed `swarm.rewind` event, all in
//! a single transaction.
//!
//! # Why it is its own module
//!
//! `src/store/postgres.rs` sits near its `qual_10_module_size_ceiling` budget
//! (ruling R6); the `postgres/reown_3124.rs` precedent. The trait arm in
//! `postgres.rs` forwards here.
//!
//! # Parity contract with the sqlite funnel
//!
//! Same control flow, same report, same metadata marker bytes: idempotent via
//! the root's `contamination.rewind` marker (no second audit event), fail-closed
//! on a root already in a stronger system-only state, zero-write dry-run
//! preview, per-row compare-and-set so a row that moved between read and write
//! is left alone (`Vanished`), never downgrade `Tombstoned` / `Quarantined`,
//! the durable memory TEXT is never touched. Cost comes from
//! [`crate::cost::postgres::lineage_rollup_pg`] — the first production reader
//! of the #3323 postgres counters.

use super::{
    CallerContext, PgSignedEventInsert, PostgresStore, StoreError, StoreResult,
    pg_append_signed_event_with_chain_in_tx, to_store_err,
};
use crate::models::LifecycleState;
use crate::storage::{
    CONTAMINATION_METADATA_KEY, SWARM_REWIND_MARKER_KEY, StampAuthority, SwarmRewindCost,
    SwarmRewindReport,
};
use crate::store::MemoryStore;

/// Per-row outcome of the contaminating compare-and-set (sqlite
/// `ContaminateOutcome` twin).
enum Stamp {
    Stamped,
    AlreadyContaminated,
    SkippedSystemOnly,
    /// Outside a non-admin caller's authority — left untouched (f1 F1).
    Unauthorized,
    Vanished,
}

/// The ownership site every PG contamination-stamp authority check is
/// labelled with (the stamp is an effect of the link write).
const STAMP_SITE: crate::identity::owner_stamp::MutationSite =
    crate::identity::owner_stamp::MutationSite::postgres(
        crate::identity::owner_stamp::funnel::LINK,
    );

/// A malformed / absent metadata blob is treated as an empty object (the
/// marker is additive, never destructive) — sqlite parity.
fn object_or_empty(v: Option<serde_json::Value>) -> serde_json::Value {
    v.filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}))
}

impl PostgresStore {
    /// Contaminate one row inside `tx` (sqlite `contaminate_row` twin).
    ///
    /// Gated in its OWN body, not only by its caller: `gate_record_stop` is an
    /// idempotent read-probe (a TTL-cached flag load), so the repeat call is
    /// cheap and this write site is self-evidently fenced for the B7 scan.
    async fn contaminate_row_pg(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        id: &str,
        contaminated_from: &str,
        now: &str,
        extra: &[(&str, serde_json::Value)],
        authority: StampAuthority<'_>,
    ) -> StoreResult<Stamp> {
        self.gate_record_stop().await?;
        let row: Option<(String, Option<serde_json::Value>)> =
            sqlx::query_as("SELECT lifecycle_state, metadata FROM memories WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| to_store_err("swarm_rewind read row", e))?;
        let Some((cur_str, meta)) = row else {
            return Ok(Stamp::Vanished);
        };
        let mut meta = object_or_empty(meta);
        if !authority.admits(&meta, id, STAMP_SITE) {
            return Ok(Stamp::Unauthorized);
        }
        let cur = LifecycleState::from_str(&cur_str).unwrap_or_default();
        if cur == LifecycleState::Contaminated {
            return Ok(Stamp::AlreadyContaminated);
        }
        if cur.is_system_only() {
            return Ok(Stamp::SkippedSystemOnly);
        }
        if let Some(map) = meta.as_object_mut() {
            map.insert(
                CONTAMINATION_METADATA_KEY.to_string(),
                crate::storage::contamination_marker::build(cur, contaminated_from, now, extra),
            );
        }
        let n = sqlx::query(
            "UPDATE memories SET lifecycle_state = $1, metadata = $2, updated_at = NOW(), \
             version = version + 1 WHERE id = $3 AND lifecycle_state = $4",
        )
        .bind(LifecycleState::Contaminated.as_str())
        .bind(&meta)
        .bind(id)
        .bind(&cur_str)
        .execute(&mut **tx)
        .await
        .map_err(|e| to_store_err("swarm_rewind stamp row", e))?
        .rows_affected();
        Ok(if n == 1 {
            Stamp::Stamped
        } else {
            Stamp::Vanished
        })
    }

    /// Item 3 part 3 (R3) — the postgres twin of
    /// [`crate::storage::stamp_contaminated_descendants`]: taint the bounded
    /// `derives_from` DESCENDANTS of a superseded root (the root itself is not
    /// stamped), in ONE transaction, with the empty extra marker the sqlite
    /// auto-stamp writes, so a row reads byte-identically whichever backend
    /// stamped it. Idempotent (already-contaminated rows are counted, not
    /// rewritten), never downgrades `Tombstoned` / `Quarantined`, and the
    /// durable memory TEXT is never touched.
    ///
    /// Runs with ADMIN authority (the whole closure); the `link_signed`
    /// trigger uses [`Self::stamp_contaminated_descendants_pg_as`].
    ///
    /// # Errors
    ///
    /// The record-stop refusal, the lineage walk, or any transaction / query
    /// failure — each rolls the whole sweep back.
    pub async fn stamp_contaminated_descendants_pg(
        &self,
        root_id: &str,
        max_depth: usize,
    ) -> StoreResult<crate::storage::ContaminationStampReport> {
        self.stamp_contaminated_descendants_pg_as(root_id, max_depth, StampAuthority::Admin)
            .await
    }

    /// [`Self::stamp_contaminated_descendants_pg`] under an explicit caller
    /// `authority` (f1-review F1): a non-admin stamps only the descendants it
    /// owns; the rest are counted in `skipped_unauthorized` (one WARN, no ids).
    async fn stamp_contaminated_descendants_pg_as(
        &self,
        root_id: &str,
        max_depth: usize,
        authority: StampAuthority<'_>,
    ) -> StoreResult<crate::storage::ContaminationStampReport> {
        self.gate_record_stop().await?;
        let descendants = self.lineage_descendants(root_id, max_depth).await?;
        let now = chrono::Utc::now().to_rfc3339();
        let mut report = crate::storage::ContaminationStampReport {
            root_id: root_id.to_string(),
            ..crate::storage::ContaminationStampReport::default()
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("contaminated stamp begin", e))?;
        for node in &descendants {
            match self
                .contaminate_row_pg(&mut tx, &node.id, root_id, &now, &[], authority)
                .await?
            {
                Stamp::Stamped => report.stamped += 1,
                Stamp::AlreadyContaminated => report.already_contaminated += 1,
                Stamp::SkippedSystemOnly => report.skipped_system_only += 1,
                Stamp::Unauthorized => report.skipped_unauthorized += 1,
                Stamp::Vanished => {}
            }
        }
        tx.commit()
            .await
            .map_err(|e| to_store_err("contaminated stamp commit", e))?;
        crate::storage::contamination_marker::warn_skipped_unauthorized(
            root_id,
            report.skipped_unauthorized,
        );
        Ok(report)
    }

    /// Item 3 part 3 (R3, amendment A13) — the postgres twin of the sqlite
    /// #3324 auto-stamp TRIGGER (`mcp/tools/link.rs`), and exactly as narrow:
    /// fires only for a `supersedes` edge whose source AND target are both
    /// `memory_kind = reflection`, and stamps the DESCENDANTS of the superseded
    /// target to [`crate::storage::LINEAGE_MAX_DEPTH`]. Called from
    /// `link_signed` (the HTTP `POST /links` path, Postgres's only link
    /// surface) AFTER the edge committed. Best-effort like sqlite: a failure
    /// logs and does NOT roll the committed edge back (the stamp is internally
    /// atomic and idempotent, so it self-heals on the next supersede).
    ///
    /// f1-review F1: the stamp is an effect of the CALLER's authority, never
    /// of source ownership alone. It runs only when `ctx` is admin
    /// (`bypass_visibility`) or owns the superseded TARGET, and a non-admin
    /// then stamps only the descendants it owns.
    pub(super) async fn stamp_on_reflection_supersedes_pg(
        &self,
        ctx: &CallerContext,
        link: &crate::models::MemoryLink,
    ) {
        if link.relation != crate::models::MemoryLinkRelation::Supersedes {
            return;
        }
        let is_reflection = |m: Option<&crate::models::Memory>| {
            m.is_some_and(|m| m.memory_kind == crate::models::MemoryKind::Reflection)
        };
        let (src, tgt) = match (
            self.get_any(&link.source_id).await,
            self.get_any(&link.target_id).await,
        ) {
            (Ok(s), Ok(t)) => (s, t),
            (Err(e), _) | (_, Err(e)) => {
                tracing::warn!(
                    target: crate::notification::invalidation::TRACE_TARGET,
                    invalidated_id = %link.target_id,
                    invalidating_id = %link.source_id,
                    "contaminated auto-stamp skipped: kind probe failed: {e}"
                );
                return;
            }
        };
        if !(is_reflection(src.as_ref()) && is_reflection(tgt.as_ref())) {
            return;
        }
        let authority = if ctx.bypass_visibility {
            StampAuthority::Admin
        } else {
            StampAuthority::Caller(ctx.effective_principal())
        };
        let max_depth = crate::storage::LINEAGE_MAX_DEPTH;
        if tgt.is_some_and(|t| !authority.admits(&t.metadata, &t.id, STAMP_SITE)) {
            let skipped = self
                .lineage_descendants(&link.target_id, max_depth)
                .await
                .map_or(0, |d| d.len());
            crate::storage::contamination_marker::warn_skipped_unauthorized(
                &link.target_id,
                skipped,
            );
            return;
        }
        if let Err(e) = self
            .stamp_contaminated_descendants_pg_as(&link.target_id, max_depth, authority)
            .await
        {
            tracing::warn!(
                target: crate::notification::invalidation::TRACE_TARGET,
                invalidated_id = %link.target_id,
                invalidating_id = %link.source_id,
                "contaminated auto-stamp failed: {e}"
            );
        }
    }

    /// Item 3 — the postgres `swarm_rewind`. `ctx.agent_id` is the issuer
    /// recorded in the signed event; the HTTP route passes the server-resolved
    /// admin principal (ruling Q1), never a wire header.
    ///
    /// # Errors
    ///
    /// Root not found, root already in a stronger system-only state, a root
    /// that changed during the rewind, the record-stop refusal, or any
    /// transaction / query / chain-append failure — each rolls the whole
    /// rewind back.
    pub(super) async fn swarm_rewind_pg(
        &self,
        ctx: &CallerContext,
        root_id: &str,
        max_depth: usize,
        target_kind: &str,
        freeze_routine_ids: &[String],
        dry_run: bool,
    ) -> StoreResult<SwarmRewindReport> {
        let root: Option<(String, Option<serde_json::Value>)> =
            sqlx::query_as("SELECT lifecycle_state, metadata FROM memories WHERE id = $1")
                .bind(root_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| to_store_err("swarm_rewind read root", e))?;
        let Some((root_state_str, root_meta)) = root else {
            return Err(StoreError::InvalidInput {
                detail: format!("swarm_rewind: root memory {root_id} not found"),
            });
        };
        let root_state = LifecycleState::from_str(&root_state_str).unwrap_or_default();
        let root_meta = object_or_empty(root_meta);
        let already_rewound = root_state == LifecycleState::Contaminated
            && root_meta[CONTAMINATION_METADATA_KEY][SWARM_REWIND_MARKER_KEY].as_bool()
                == Some(true);

        let descendants = self.lineage_descendants(root_id, max_depth).await?;
        let rollup = crate::cost::postgres::lineage_rollup_pg(&self.pool, root_id, max_depth)
            .await
            .map_err(|e| to_store_err("swarm_rewind lineage cost", e))?;
        let mut report = SwarmRewindReport {
            root_id: root_id.to_string(),
            target_kind: target_kind.to_string(),
            dry_run,
            descendants_total: descendants.len(),
            routines_requested: freeze_routine_ids.len(),
            cost: SwarmRewindCost::from_rollup(&rollup),
            ..SwarmRewindReport::default()
        };
        if already_rewound {
            report.already_rewound = true;
            return Ok(report);
        }
        if root_state.is_system_only() && root_state != LifecycleState::Contaminated {
            return Err(StoreError::InvalidInput {
                detail: format!(
                    "swarm_rewind: root memory {root_id} is in a system-only terminal state \
                     ({}); already contained, nothing to rewind",
                    root_state.as_str()
                ),
            });
        }

        if dry_run {
            report.root_contaminated = root_state != LifecycleState::Contaminated;
            for node in &descendants {
                let st: Option<(String,)> =
                    sqlx::query_as("SELECT lifecycle_state FROM memories WHERE id = $1")
                        .bind(&node.id)
                        .fetch_optional(&self.pool)
                        .await
                        .map_err(|e| to_store_err("swarm_rewind preview", e))?;
                match st.and_then(|(s,)| LifecycleState::from_str(&s)) {
                    Some(LifecycleState::Contaminated) => {
                        report.descendants_already_contaminated += 1;
                    }
                    Some(s) if s.is_system_only() => report.descendants_skipped_system_only += 1,
                    Some(_) => report.descendants_stamped += 1,
                    None => {}
                }
            }
            return Ok(report);
        }

        // Real run: fail-closed record-plane fence, then ONE transaction.
        self.gate_record_stop().await?;
        let now_dt = chrono::Utc::now();
        let now = now_dt.to_rfc3339();
        let via = serde_json::json!(crate::governance::action_labels::SWARM_REWIND);

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("swarm_rewind begin", e))?;

        // 1a. The downstream cascade.
        let desc_extra = [("via", via.clone())];
        for node in &descendants {
            match self
                .contaminate_row_pg(
                    &mut tx,
                    &node.id,
                    root_id,
                    &now,
                    &desc_extra,
                    StampAuthority::Admin,
                )
                .await?
            {
                Stamp::Stamped => report.descendants_stamped += 1,
                Stamp::AlreadyContaminated => report.descendants_already_contaminated += 1,
                Stamp::SkippedSystemOnly => report.descendants_skipped_system_only += 1,
                Stamp::Unauthorized | Stamp::Vanished => {}
            }
        }

        // 1b. The root, carrying the `rewind: true` idempotency marker.
        if root_state == LifecycleState::Contaminated {
            // Already tainted (a prior stamp as another root's descendant):
            // upgrade its marker in place, keeping the prior-state anchor. CAS
            // on the observed state; 0 rows means the root moved — roll back
            // (the sqlite #3327 Sec-F4 fail-closed rule).
            let mut meta = root_meta.clone();
            if let Some(obj) = meta.as_object_mut() {
                let mut cont = obj
                    .get(CONTAMINATION_METADATA_KEY)
                    .and_then(serde_json::Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                cont.insert(SWARM_REWIND_MARKER_KEY.to_string(), serde_json::json!(true));
                cont.insert("via".to_string(), via.clone());
                cont.insert(
                    crate::storage::contamination_marker::REWOUND_AT_KEY.to_string(),
                    serde_json::json!(now),
                );
                obj.insert(
                    CONTAMINATION_METADATA_KEY.to_string(),
                    serde_json::Value::Object(cont),
                );
            }
            let n = sqlx::query(
                "UPDATE memories SET metadata = $1, updated_at = NOW(), version = version + 1 \
                 WHERE id = $2 AND lifecycle_state = $3",
            )
            .bind(&meta)
            .bind(root_id)
            .bind(LifecycleState::Contaminated.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err("swarm_rewind root marker", e))?
            .rows_affected();
            if n != 1 {
                return Err(StoreError::InvalidInput {
                    detail: format!(
                        "swarm_rewind: root {root_id} changed during rewind (contaminated \
                         marker CAS matched no row); transaction rolled back"
                    ),
                });
            }
            report.root_contaminated = false;
        } else {
            let root_extra = [
                (SWARM_REWIND_MARKER_KEY, serde_json::json!(true)),
                ("via", via.clone()),
            ];
            match self
                .contaminate_row_pg(
                    &mut tx,
                    root_id,
                    root_id,
                    &now,
                    &root_extra,
                    StampAuthority::Admin,
                )
                .await?
            {
                Stamp::Stamped => report.root_contaminated = true,
                _ => {
                    return Err(StoreError::InvalidInput {
                        detail: format!(
                            "swarm_rewind: root {root_id} changed during rewind; transaction \
                             rolled back"
                        ),
                    });
                }
            }
        }

        // 2. Freeze the operator-named routines inside the SAME transaction
        //    (the pool-level `routine_freeze` would commit outside it). Draft
        //    -> Frozen only; an already-frozen routine keeps its frozen_at and
        //    still counts, a missing id does not (sqlite parity).
        let frozen = crate::models::RoutineState::Frozen.as_str();
        for rid in freeze_routine_ids {
            sqlx::query(
                "UPDATE routines SET state = $1, frozen_at = $2 WHERE id = $3 AND state = $4",
            )
            .bind(frozen)
            .bind(now_dt.timestamp())
            .bind(rid)
            .bind(crate::models::RoutineState::Draft.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err("swarm_rewind freeze routine", e))?;
            let st: Option<(String,)> = sqlx::query_as("SELECT state FROM routines WHERE id = $1")
                .bind(rid)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| to_store_err("swarm_rewind read routine", e))?;
            if st.is_some_and(|(s,)| s == frozen) {
                report.routines_frozen += 1;
            }
        }

        // 3. The signed `swarm.rewind` event, same canonical payload as sqlite.
        let payload = crate::storage::swarm_rewind_audit_payload(
            root_id,
            target_kind,
            report.descendants_stamped,
            report.routines_frozen,
            &ctx.agent_id,
            &now,
        )
        .map_err(|e| StoreError::BackendUnavailable {
            backend: "postgres".to_string(),
            detail: format!("swarm_rewind audit payload: {e}"),
            sqlstate: None,
        })?;
        let event = crate::signed_events::SignedEvent::with_daemon_signature(
            crate::signed_events::payload_hash(&payload),
            ctx.agent_id.clone(),
            crate::signed_events::event_types::SWARM_REWIND.to_string(),
            now.clone(),
            None,
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
                timestamp: now_dt,
                cause_hash: event.cause_hash.as_deref(),
            },
        )
        .await
        .map_err(|e| to_store_err("swarm_rewind append signed_event", e))?;
        tx.commit()
            .await
            .map_err(|e| to_store_err("swarm_rewind commit", e))?;
        report.signed_event_id = Some(event.id);
        Ok(report)
    }
}
