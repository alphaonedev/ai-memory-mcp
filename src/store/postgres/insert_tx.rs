// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Transaction-composable create funnel (#3587). The caller owns rollback/commit.

use super::{
    COL_CONFIDENCE_SIGNALS, COL_SOURCE_SPAN, CallerContext, Memory, PostgresStore,
    READ_RETURNED_ID, SQL_DELETE_FORGET_TOMBSTONE_BY_MEMORY_ID, StoreError, StoreResult,
    consult_governance_pre_write_pg, consult_why_trace_gate_pg, memory_storage_bytes,
    parse_rfc3339_opt, parse_rfc3339_required, pg_emit_revision_leaf_if_enabled,
    pg_probe_upsert_prior_version, reconcile_envelope_owner, record_memory_quota_in_tx,
    resolve_quota_agent_id, screen_storage_memory, seal_content_for_upsert, serialize_err,
    to_store_err,
};
use crate::store::record_stop::gate_flag as gate_record_stop_cached;
use sqlx::Row;

impl PostgresStore {
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub(super) async fn store_with_embedding_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ctx: &CallerContext,
        memory: &Memory,
        embedding: Option<&[f32]>,
        space: Option<&str>,
        conflict_arm: crate::storage::InsertConflictArm,
    ) -> StoreResult<String> {
        gate_record_stop_cached(&self.record_stop)?;
        // v0.8.1 W1 (#1821 / gap G29) — credential REDACT backstop (postgres
        // parity); masks before the embedding + bind. No-op unless seeded.
        let screened = screen_storage_memory(memory);
        let memory = screened.as_ref().unwrap_or(memory);
        // ARCH-1 (CRITICAL) — substrate governance pre-write parity.
        // The semantic-recall write path MUST consult the hook just
        // like the plain `store` path; otherwise an operator-signed
        // refuse rule could be bypassed by routing through the
        // embedded-vector path. See `src/storage/mod.rs` for context.
        consult_governance_pre_write_pg(memory)?;
        // #2059/#2102/#2110 — clause 1 on the embed-before-store hot path (the
        // PRIMARY create anchor on postgres daemons).
        // #2124 — stamp the SAME substrate why_trace the sqlite
        // `SqliteStore::store` funnel stamps (src/store/sqlite.rs) BEFORE the
        // gate, then consult the gate UNCONDITIONALLY as defense-in-depth. Pre
        // #2124 this funnel SKIPPED the gate under `bypass_visibility` WITHOUT
        // stamping, so an internally-authored row landed with NO clause-1
        // rationale on postgres while sqlite recorded the substrate marker —
        // cross-backend provenance drift. Mirrors the pg
        // reflect/capture_turn/consolidate funnels.
        let stamped_holder;
        let memory = if ctx.bypass_visibility {
            let mut m = memory.clone();
            crate::storage::stamp_substrate_why_trace(&mut m.metadata);
            stamped_holder = m;
            &stamped_holder
        } else {
            memory
        };
        consult_why_trace_gate_pg(memory)?;

        // Same upsert contract as `store` but additionally writes the
        // pgvector `embedding` column when a vector is supplied. This
        // is the load-bearing path for semantic recall on postgres —
        // without an embedding column the `recall_hybrid` cosine
        // search filters out every row (`WHERE embedding IS NOT NULL`).
        let created_at = parse_rfc3339_required(&memory.created_at)?;
        let updated_at = parse_rfc3339_required(&memory.updated_at)?;
        let last_accessed_at = parse_rfc3339_opt(memory.last_accessed_at.as_deref());
        // v0.7.0 #1466 — backfill the tier-default expiry so a hand-built
        // mid/short Memory with `expires_at: None` is reapable, matching the
        // SQLite `storage::insert` chokepoint. Shared SSOT on `Memory`.
        let expires_at = parse_rfc3339_opt(memory.effective_expires_at().as_deref());
        let tags_json =
            serde_json::to_value(&memory.tags).map_err(|e| StoreError::IntegrityFailed {
                detail: serialize_err("tags", e),
            })?;
        let emb_pgvec = embedding.map(|v| pgvector::Vector::from(v.to_vec()));
        // #2167 — the vector's provenance stamp travels in the SAME
        // statement as the vector (the §2 same-statement rule). Stamp
        // `space` ONLY when a vector is actually written, so a NULL
        // embedding never lands a lying `embedding_space`.
        let emb_space: Option<&str> = embedding.and_then(|_| space);
        // #1608 — Form-4 / Form-5 / QW-2 column parity with `store()`
        // and `apply_remote_memory`. Pre-#1608 this INSERT listed only
        // 19 columns, so the embed-before-store hot path (the HTTP
        // create anchor on postgres daemons) silently dropped
        // citations / source_uri / source_span / confidence_source /
        // confidence_signals / confidence_decayed_at / entity_id /
        // persona_version — every attested HTTP create landed with the
        // schema-default `confidence_source = 'caller_provided'` while
        // the wire response and the federation SHIP envelope carried
        // the truthful handler-stamped value (the #1588 DO-leg lived
        // contradiction: anchor row lied, receiver rows were correct).
        // Same defect class as #1029 on `apply_remote_memory`.
        let citations_json =
            serde_json::to_string(&memory.citations).map_err(|e| StoreError::IntegrityFailed {
                detail: serialize_err("citations", e),
            })?;
        let source_span_json = match &memory.source_span {
            Some(span) => {
                Some(
                    serde_json::to_string(span).map_err(|e| StoreError::IntegrityFailed {
                        detail: serialize_err(COL_SOURCE_SPAN, e),
                    })?,
                )
            }
            None => None,
        };
        let confidence_signals_json = match &memory.confidence_signals {
            Some(s) => Some(
                serde_json::to_string(s).map_err(|e| StoreError::IntegrityFailed {
                    detail: serialize_err(COL_CONFIDENCE_SIGNALS, e),
                })?,
            ),
            None => None,
        };

        // APPEND-ONLY-SANCTIONED (#1823 G6 / #2948) — COW SUPERSEDE: probe the
        // existing (title, namespace) row's version BEFORE the upsert. On the
        // Merge arm a conflict overwrites content in place (and a same-id
        // RestoreSameId re-store does too); the Refuse / different-id
        // RestoreSameId arms return the typed Conflict below WITHOUT overwriting,
        // so they never reach the leaf emit. `None` when the spine is OFF or on a
        // fresh INSERT. Same tx.
        let prior_version = pg_probe_upsert_prior_version(tx, &memory.title, &memory.namespace)
            .await
            .map_err(|e| to_store_err("probe upsert prior version", e))?;

        // #1383 — same denormalisation rationale as the regular
        // `store()` path above. Reflection-kind rows passed through
        // `store_with_embedding` (the recall-hybrid hot path) must
        // still light up the `mentioned_entity_id` partial index.
        let mentioned_entity_id = crate::storage::extract_mentioned_entity_id(memory);
        // v0.9.0 G8 (#1825) — the embed-before-store hot path mints a genesis
        // row, so it stamps its own content-id from the (plaintext) memory
        // identity. OMITTED from the DO UPDATE SET below: a surviving
        // upsert-merge row keeps its own genesis cid.
        let embed_cid = crate::identity::cid::stamp_memory_cid(memory);
        // #2292 — at-rest content-seal on the PRIMARY embedded-write hot path
        // (every semantic-tier store). Pre-#2292 this funnel bound
        // `memory.content` PLAINTEXT and omitted `encrypted_envelope`, so an
        // `AI_MEMORY_ENCRYPT_AT_REST` deployment leaked plaintext on its
        // busiest write path while `store()` sealed. Content arm is
        // unconditional (`content = EXCLUDED.content`), so the envelope moves
        // with it unconditionally on the ON CONFLICT arm below.
        // v1.0.0 #2383 (N1) — sealed to the identity the SURVIVING row RETAINS,
        // not the incoming writer: the `ON CONFLICT` arm keeps the existing row's
        // `agent_id` (#1784) while taking the incoming envelope, so an
        // incoming-keyed seal left the durable row unreadable. Same tx as the
        // upsert, so the pre-read + write are one atomic unit.
        let embed_seal = seal_content_for_upsert(&mut **tx, memory).await?;
        let (embed_content, embed_envelope) = (embed_seal.content(), embed_seal.envelope());

        let embed_upsert_sql = "INSERT INTO memories (
                id, tier, namespace, title, content, tags, priority, confidence,
                source, access_count, created_at, updated_at, last_accessed_at,
                expires_at, metadata, reflection_depth, memory_kind,
                citations, source_uri, source_span,
                confidence_source, confidence_signals, confidence_decayed_at,
                entity_id, persona_version, embedding,
                mentioned_entity_id, lifecycle_state,
                cid, cid_genesis, embedding_space,
                valid_from, valid_until, encrypted_envelope, kind_provenance
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17,
                      $18, $19, $20,
                      $21, $22, $23,
                      $24, $25, $26,
                      $27, $28, $29, $30, $31,
                      $32, $33, $34, $35)
            ON CONFLICT (title, namespace) DO UPDATE SET
                content = EXCLUDED.content,
                -- #2292 — content + envelope move together on upsert so a
                -- re-store replaces both the placeholder and the ciphertext
                -- (encryption-off writes plaintext + NULL, clearing any stale
                -- ciphertext). Mirrors `store()` / `store_batch()`.
                encrypted_envelope = EXCLUDED.encrypted_envelope,
                tier = CASE
                    WHEN tier_rank(EXCLUDED.tier) >= tier_rank(memories.tier)
                        THEN EXCLUDED.tier
                    ELSE memories.tier
                END,
                tags = EXCLUDED.tags,
                -- #1629 — sqlite parity: MAX-merge, source follows incoming,
                -- expiry long→NULL + COALESCE (see `store()` for rationale).
                priority = GREATEST(memories.priority, EXCLUDED.priority),
                confidence = GREATEST(memories.confidence, EXCLUDED.confidence),
                source = EXCLUDED.source,
                updated_at = EXCLUDED.updated_at,
                -- v1.0.0 #2515 (GA Wave-1 data-integrity blocker) — a re-store /
                -- upsert must FLOOR the TTL, never SHORTEN it. The bare
                -- COALESCE(EXCLUDED.expires_at, memories.expires_at) adopted the
                -- incoming row's expiry verbatim, so re-storing the same
                -- (title, namespace) with an EARLIER expiry silently rolled a
                -- live row's TTL backwards — a #1596 never-move-expiry-earlier
                -- violation (premature GC reap / permanent link-edge loss). This
                -- mirrors EXACTLY the shipped #2335 federation extension-FLOOR
                -- lattice join (GREATEST over the COALESCE'd pair, both operands
                -- funnel-canonical per #2332): the merge converges on the LATER
                -- expiry regardless of store order. Long⇒NULL keeps the #1626
                -- coupling. EXPLICIT shortening stays ONLY on the memory_update /
                -- db::update path, never on this re-store funnel.
                expires_at = CASE
                    WHEN EXCLUDED.tier = 'long' OR memories.tier = 'long' THEN NULL
                    ELSE GREATEST(COALESCE(EXCLUDED.expires_at, memories.expires_at),
                                  COALESCE(memories.expires_at, EXCLUDED.expires_at))
                END,
                metadata = (EXCLUDED.metadata || (
                    -- #1784 — preserve immutable provenance keys (agent_id +
                    -- consolidation derived_from / consolidated_from_agents)
                    -- from the existing row through the metadata overwrite.
                    -- `||` overlays them on top of EXCLUDED so existing wins
                    -- (the superset of the pre-#1784 agent_id-only CASE).
                    SELECT COALESCE(jsonb_object_agg(prov.k, prov.v), '{}'::jsonb)
                    FROM jsonb_each(memories.metadata) AS prov(k, v)
                    -- #2941 — reserved set, lockstep-gated on crate::RESERVED_UPSERT_METADATA_KEYS.
                    WHERE prov.k IN ('agent_id', 'derived_from', 'consolidated_from_agents', 'agent_pubkey', 'pubkey_bound_at')
                )),
                -- v0.7.0 Task 1/8 — recursion depth takes max on upsert.
                reflection_depth = GREATEST(memories.reflection_depth, EXCLUDED.reflection_depth),
                -- L1-1 — kind is sticky (reflection AND persona, #1629).
                memory_kind = CASE WHEN memories.memory_kind = 'reflection' THEN 'reflection'
                                   WHEN memories.memory_kind = 'persona' THEN 'persona'
                                   ELSE EXCLUDED.memory_kind END,
                -- #1608 / #1629 — Form-4 / Form-5 / QW-2 arms mirror `store()`
                -- (sqlite shape): re-store doesn't blank out provenance.
                citations = CASE WHEN EXCLUDED.citations = '[]'
                                 THEN memories.citations
                                 ELSE EXCLUDED.citations END,
                source_uri = COALESCE(EXCLUDED.source_uri, memories.source_uri),
                source_span = COALESCE(EXCLUDED.source_span, memories.source_span),
                -- v1.0.0 #2395 — the confidence field-set is ATOMIC (sqlite
                -- twin in `storage::insert_inner`'s `upsert_sql`). `confidence`
                -- merges by GREATEST above, so the calibration record that
                -- DESCRIBES that number must come from the SAME operand that
                -- won. Pre-#2395 these three used a DIFFERENT selector, so a
                -- re-store with a LOWER confidence but a non-default source
                -- kept the stored 0.9 and stamped the incoming label + signals
                -- over it — durable Form-5 corruption, silent to every reader.
                -- Selector = the GREATEST winner: > takes the incoming tuple,
                -- < keeps the stored tuple, and an exact tie keeps the #1629
                -- rule verbatim (explicit non-`caller_provided` replaces) but
                -- now carries the WHOLE tuple. `=` is only the tie BRANCH of a
                -- total order, never a logical float-equality test.
                confidence_source = CASE WHEN EXCLUDED.confidence > memories.confidence THEN EXCLUDED.confidence_source
                                         WHEN EXCLUDED.confidence < memories.confidence THEN memories.confidence_source
                                         WHEN EXCLUDED.confidence_source != 'caller_provided' THEN EXCLUDED.confidence_source
                                         ELSE memories.confidence_source END,
                confidence_signals = CASE WHEN EXCLUDED.confidence > memories.confidence THEN EXCLUDED.confidence_signals
                                          WHEN EXCLUDED.confidence < memories.confidence THEN memories.confidence_signals
                                          WHEN EXCLUDED.confidence_source != 'caller_provided' THEN EXCLUDED.confidence_signals
                                          ELSE memories.confidence_signals END,
                confidence_decayed_at = CASE WHEN EXCLUDED.confidence > memories.confidence THEN EXCLUDED.confidence_decayed_at
                                             WHEN EXCLUDED.confidence < memories.confidence THEN memories.confidence_decayed_at
                                             WHEN EXCLUDED.confidence_source != 'caller_provided' THEN EXCLUDED.confidence_decayed_at
                                             ELSE memories.confidence_decayed_at END,
                entity_id = COALESCE(memories.entity_id, EXCLUDED.entity_id),
                persona_version = COALESCE(memories.persona_version, EXCLUDED.persona_version),
                embedding = COALESCE(EXCLUDED.embedding, memories.embedding),
                -- #2167 — the stamp travels WITH the vector on the upsert-
                -- merge arm too: when the incoming vector replaces the
                -- stored one, its space replaces the stored stamp; when the
                -- incoming vector is NULL (COALESCE keeps the old vector),
                -- the old stamp is kept. A same-dim model swap-back can
                -- therefore never leave a stamp attesting a foreign vector.
                embedding_space = CASE
                    WHEN EXCLUDED.embedding IS NOT NULL THEN EXCLUDED.embedding_space
                    ELSE memories.embedding_space
                END,
                -- #1383 — preserve a previously-extracted attribution
                -- if EXCLUDED is NULL (sqlite parity).
                mentioned_entity_id = COALESCE(EXCLUDED.mentioned_entity_id, memories.mentioned_entity_id),
                -- v0.8.0 Pillar 2 (#1709) — lifecycle_state preserved on
                -- re-store (sqlite parity); advances go through the typed
                -- update gate.
                lifecycle_state = memories.lifecycle_state,
                -- v1.0.0 #2267 / #1834 — match the plain `store()`
                -- claim-bitemporal contract: genesis is immutable while a
                -- newly supplied upper bound may close the existing claim.
                valid_from = memories.valid_from,
                valid_until = COALESCE(EXCLUDED.valid_until, memories.valid_until),
                -- v0.9.0 G8 (#1825) — cid/cid_genesis OMITTED from DO UPDATE
                -- SET: surviving row keeps its genesis.
                -- #1632 (pg twin) — upsert-merge bumps the Gap-1 counter.
                version = memories.version + 1,
                -- v1.0.0 #2393 (N12) — sqlite parity: the epistemic-typing
                -- provenance follows the incoming write when present, else
                -- keeps the stored marker (the `store()` COALESCE precedent).
                -- v1.0.0 #2394 — the epistemic-typing provenance FOLLOWS THE
                -- KIND THAT ACTUALLY WON. `memory_kind` above is sticky (a
                -- stored `reflection` / `persona` is never downgraded), but the
                -- bare COALESCE adopted the incoming provenance unconditionally,
                -- so a row that KEPT its stored kind was relabelled with the
                -- REJECTED write's provenance — durable metadata attesting a
                -- kind the merge threw away. The CASE mirrors the `memory_kind`
                -- CASE above exactly (kind unchanged -> the #1945/#2393
                -- COALESCE; stored sticky kind survived -> keep the stored
                -- provenance; incoming kind adopted -> its provenance verbatim,
                -- NULL included) and is NULL-safe by construction.
                kind_provenance = CASE WHEN EXCLUDED.memory_kind = memories.memory_kind
                                            THEN COALESCE(EXCLUDED.kind_provenance, memories.kind_provenance)
                                       WHEN memories.memory_kind IN ('reflection', 'persona')
                                            THEN memories.kind_provenance
                                       ELSE EXCLUDED.kind_provenance END
            RETURNING id";
        // #2771/#2887 — single-source the column list + binds + the whole DO
        // UPDATE SET arm across every disposition; only the ON CONFLICT
        // resolution differs, derived from the ONE upsert literal so a future
        // column add can never miss one. `Merge` = the literal verbatim; `Refuse`
        // (#2771) = `DO NOTHING` (refuse ANY collision); `RestoreSameId` (#2887) =
        // the same DO UPDATE SET arm with `WHERE memories.id = EXCLUDED.id` (the
        // CAS: merge a same-id restore, skip — no RETURNed row — a foreign-id
        // owner, mirroring the sqlite `insert_inner` twin).
        let embed_sql: std::borrow::Cow<'_, str> = match conflict_arm {
            crate::storage::InsertConflictArm::Merge => {
                std::borrow::Cow::Borrowed(embed_upsert_sql)
            }
            crate::storage::InsertConflictArm::Refuse => {
                let head = embed_upsert_sql
                    .split("ON CONFLICT")
                    .next()
                    .unwrap_or(embed_upsert_sql);
                std::borrow::Cow::Owned(
                    [
                        head,
                        "ON CONFLICT (title, namespace) DO NOTHING\n            RETURNING id",
                    ]
                    .concat(),
                )
            }
            crate::storage::InsertConflictArm::RestoreSameId => {
                let body = embed_upsert_sql
                    .rsplit_once("RETURNING id")
                    .map_or(embed_upsert_sql, |(head, _)| head);
                std::borrow::Cow::Owned(
                    [
                        body,
                        "WHERE memories.id = EXCLUDED.id\n            RETURNING id",
                    ]
                    .concat(),
                )
            }
        };
        let id: Option<String> = sqlx::query(&embed_sql)
            .bind(&memory.id)
            .bind(memory.tier.as_str())
            .bind(&memory.namespace)
            .bind(&memory.title)
            // #2292 — sealed placeholder ("" under an enabled gate, else verbatim).
            .bind(&embed_content)
            .bind(&tags_json)
            .bind(memory.priority)
            .bind(memory.confidence)
            .bind(&memory.source)
            .bind(memory.access_count)
            .bind(created_at)
            .bind(updated_at)
            .bind(last_accessed_at)
            .bind(expires_at)
            .bind(&memory.metadata)
            .bind(memory.reflection_depth)
            .bind(memory.memory_kind.as_str())
            .bind(&citations_json)
            .bind(memory.source_uri.as_deref())
            .bind(source_span_json.as_deref())
            .bind(memory.confidence_source.as_str())
            .bind(confidence_signals_json.as_deref())
            .bind(memory.confidence_decayed_at.as_deref())
            .bind(memory.entity_id.as_deref())
            .bind(memory.persona_version)
            .bind(emb_pgvec)
            .bind(mentioned_entity_id.as_deref())
            .bind(memory.lifecycle_state.as_str())
            .bind(&embed_cid.cid)
            .bind(&embed_cid.genesis)
            .bind(emb_space)
            // v1.0.0 #2267 — this hot path used to omit both durable columns.
            // Canonicalize at the same boundary as plain `store()` (#2265/v86).
            .bind(crate::validate::canonical_valid_time_opt(
                memory.valid_from.as_deref(),
            ))
            .bind(crate::validate::canonical_valid_time_opt(
                memory.valid_until.as_deref(),
            ))
            // #2292 — sealed ciphertext envelope ($34); NULL when encryption off.
            .bind(embed_envelope)
            // v1.0.0 #2393 (N12) — the v79/#1945 epistemic-typing provenance ($35).
            // This is the PRIMARY embedded-write hot path (every semantic-tier
            // store); sqlite has no override, so its trait default forwards to
            // `store()` → `storage::insert`, which binds the column. Omitting it
            // here landed NULL on postgres for the busiest write funnel.
            .bind(crate::storage::extract_kind_provenance(memory))
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| to_store_err("insert memory_with_embedding", e))?
            .map(|r| r.try_get::<String, _>("id"))
            .transpose()
            .map_err(|e| to_store_err(READ_RETURNED_ID, e))?;
        // #2771/#2887 — a non-Merge arm inserted nothing → a DIFFERENT id holds
        // (title, namespace): `Refuse` (DO NOTHING) on ANY collision;
        // `RestoreSameId` on a foreign-id owner (the CAS WHERE memories.id =
        // EXCLUDED.id is false → skip, no RETURNed row). Refuse fail-closed with
        // the typed conflict — NEVER overwrite. Re-probe the occupant's id in-tx
        // best-effort; a TOCTOU gap (winner deleted between the conflict and this
        // read) degrades to an empty id, never a retry-as-create. `Merge` always
        // RETURNs a row, so this branch is unreachable under it.
        let id = match id {
            Some(id) => id,
            None => {
                let existing = sqlx::query_scalar::<_, String>(
                    "SELECT id FROM memories WHERE title = $1 AND namespace = $2",
                )
                .bind(&memory.title)
                .bind(&memory.namespace)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| to_store_err("conflict existing-id probe", e))?
                .unwrap_or_default();
                return Err(StoreError::Conflict { id: existing });
            }
        };

        // #2383 (N1) — invariant backstop, same tx: a non-NULL
        // `encrypted_envelope` MUST open under the row's persisted
        // `metadata.agent_id`. Repairs the concurrent-first-creation race the
        // pre-read cannot close under READ COMMITTED.
        reconcile_envelope_owner(&mut **tx, &id, &memory.content, &embed_seal).await?;

        // v1.0.0 #2948 — record the COW SUPERSEDE for an in-place content
        // overwrite (a Merge conflict-merge, or a same-id RestoreSameId re-store).
        // A fresh INSERT leaves `prior_version` None; the Refuse / foreign-id
        // RestoreSameId arms already returned Conflict above. Identity-only, same tx.
        if let Some(prior_version) = prior_version {
            pg_emit_revision_leaf_if_enabled(
                tx,
                &id,
                crate::revisions::RecordKind::Supersede,
                Some(prior_version),
                &memory.namespace,
                Some(crate::storage::memory_agent_id(memory)).filter(|s| !s.is_empty()),
                &memory.updated_at,
            )
            .await
            .map_err(|e| to_store_err("append supersede revision leaf", e))?;
        }

        // #3272 C-2 — on an EXPLICIT operator/rollback RESTORE only, clear any
        // FORGET tombstone for the restored id so the revived original is
        // federation-syncable (`insert_if_newer` drops tombstoned ids) and
        // re-importable (Portability-v2 refuses them) again. Consolidate's
        // hard-delete arm (#3192) tombstones every source; a `curator
        // --rollback` re-inserting the originals via `restore_or_conflict`
        // otherwise leaves them silently federation-deaf. GATED on the
        // `RestoreSameId` arm — a normal federation apply / import NEVER reaches
        // here, so this cannot re-open LWW resurrection of a genuinely-deleted
        // id. Same tx as the insert (sqlite twin: `db::insert_inner`).
        if matches!(
            conflict_arm,
            crate::storage::InsertConflictArm::RestoreSameId
        ) {
            sqlx::query(SQL_DELETE_FORGET_TOMBSTONE_BY_MEMORY_ID)
                .bind(&id)
                .execute(&mut **tx)
                .await
                .map_err(|e| to_store_err("restore clear forget tombstone", e))?;
        }

        // v0.7.0 #1156 — per-namespace quota dimension (v50 PK).
        let quota_agent_id = resolve_quota_agent_id(ctx, &memory.metadata);
        let bytes_added = memory_storage_bytes(memory);
        // #2311 — tenant callers get the atomic in-tx ceiling guard (the
        // handler's `check_memory_quota` pre-check remains only the
        // fast-fail 429 shape); admin/curator contexts stay record-only,
        // matching the sqlite surface-enforcement scoping.
        record_memory_quota_in_tx(
            tx,
            &quota_agent_id,
            &memory.namespace,
            bytes_added,
            !ctx.bypass_visibility,
        )
        .await?;

        Ok(id)
    }
}
