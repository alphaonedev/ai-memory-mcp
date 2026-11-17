// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9405 / #9273 - the gated update funnel behind [`update_with_expected_version`]:
//! the #1955 record-stop gate, then ONE write transaction (opened or joined)
//! holding the stored-row read, the `_agents` ledger projection, the sealed-row
//! probe and the UPDATE. The gate and the write SQL share this one fn span so
//! the B7 structural scanner credits the gate to the fn that writes. Own child
//! module so `src/storage/mod.rs` stays under its qual_10 module-size ceiling
//! (submodule over a ceiling bump, the `title_slot_archive` precedent).

use super::*;

/// #9405 / #9273 - the gated body of [`update_with_expected_version`]: the
/// record-stop gate runs first (before any transaction is opened, so a stopped
/// store refuses without taking the write lock), then the reads and the UPDATE
/// run inside one write transaction and see one snapshot under the write lock.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) fn update_with_expected_version_in_txn(
    conn: &Connection,
    id: &str,
    title: Option<&str>,
    content: Option<&str>,
    tier: Option<&Tier>,
    namespace: Option<&str>,
    tags: Option<&Vec<String>>,
    priority: Option<i32>,
    confidence: Option<f64>,
    expires_at: Option<&str>,
    metadata: Option<&serde_json::Value>,
    source_uri: Option<&str>,
    expected_version: Option<i64>,
    // v1.0.0 #1834 — opt-in claim-bitemporal `valid_until` patch. `None` leaves
    // the stored value alone (COALESCE at the SQL layer); `Some(v)` closes/moves
    // the claim's valid interval. `valid_from` is IMMUTABLE — it is never in the
    // UPDATE SET list, so it is always preserved (the genesis assertion instant).
    valid_until: Option<&str>,
) -> Result<(bool, bool)> {
    // #1955 R45 — record-stop fence for the update funnel. It runs before the
    // transaction opens: a stopped store refuses without taking the write lock.
    crate::storage::record_stop::gate_storage_conn(conn)?;
    // #9405 - every read the write depends on (the stored row, the `_agents`
    // ledger projection, the sealed-row probe) and the UPDATE run in ONE
    // write transaction (BEGIN IMMEDIATE, or the caller's): a bind / rebind /
    // revoke cannot commit between the projection read and the row write.
    // decision: project inside the transaction over retrying on guard abort,
    // because the retry hides the race and the invariant is one transaction.
    connection::in_write_txn(conn, || {
        let mut stmt = conn.prepare_cached(SQL_SELECT_MEMORY_ROW_BY_ID)?;
        let mut rows = stmt.query_map(params![id], row_to_memory)?;
        let Some(Ok(existing)) = rows.next() else {
            return Ok((false, false));
        };
        drop(rows);
        drop(stmt);

        // v1.0.0 #1834 (pre-ship 3x7) — canonicalize the opt-in `valid_until`
        // patch at this funnel so the close instant persists in the fixed UTC
        // rendering the TEXT predicates compare correctly (a `Z`/offset-rendered
        // close would otherwise mis-order against a canonical `valid_at`).
        let valid_until_canon = crate::validate::canonical_valid_time_opt(valid_until);
        let valid_until = valid_until_canon.as_deref();

        // v0.7.0 Provenance Gap 1 (#884) — pre-check optimistic gate.
        // The same predicate is also asserted atomically inside the
        // UPDATE statement below so a racing writer that slipped in
        // between the SELECT and the UPDATE still fails CONFLICT.
        if let Some(expected) = expected_version
            && existing.version != expected
        {
            return Err(VersionConflict {
                id: existing.id.clone(),
                expected,
                current: existing.version,
            }
            .into());
        }

        let new_title = title.unwrap_or(&existing.title);
        let new_content = content.unwrap_or(&existing.content);
        let content_changed = new_title != existing.title || new_content != existing.content;

        // Tier downgrade protection: never downgrade, consistent with insert path.
        let effective_tier = match (tier, &existing.tier) {
            (Some(requested), existing_tier) => match (existing_tier, requested) {
                (Tier::Long, _) => &Tier::Long,         // long never downgrades
                (Tier::Mid, Tier::Short) => &Tier::Mid, // mid never downgrades to short
                (_, requested) => requested,            // upgrades and same-tier are fine
            },
            (None, existing_tier) => existing_tier,
        };

        let namespace = namespace.unwrap_or(&existing.namespace);
        let tags = tags.unwrap_or(&existing.tags);
        let priority = priority.unwrap_or(existing.priority);
        let confidence = confidence.unwrap_or(existing.confidence);
        // Treat empty string as None (clear expiry) — don't store "" in the DB
        let expires_at = match expires_at {
            Some("" | "null") => None,
            Some(v) => Some(v),
            None => existing.expires_at.as_deref(),
        };
        // v1.0.0 #2331 (FBL-01) — the #1626 tier→long ⇒ expires_at = NULL
        // coupling, sqlite parity with BOTH postgres update funnels
        // (`update_with_expected_version_once` + the trait `update`) and with
        // this file's own insert ON CONFLICT arm / fold auto-promote / both
        // promote surfaces. When the EFFECTIVE tier is Long the merged expiry
        // is forced NULL — overriding a caller-supplied patch value AND the
        // existing row's stale short/mid TTL — because the GC reap predicate
        // is tier-blind (`expires_at IS NOT NULL AND expires_at < now`), so a
        // leftover TTL on a promoted "permanent" row would archive it (or
        // hard-delete + crypto-erase it under archive_on_gc=false) at the
        // stale deadline. Silent destruction of a documented-permanent row is
        // a direct North-Star data-integrity violation.
        let expires_at = if matches!(*effective_tier, Tier::Long) {
            None
        } else {
            expires_at
        };
        // v1.0.0 #2332 (FBL-02) — canonicalize the merged expiry (caller patch
        // OR carried-forward stored value) to the fixed-UTC v86 rendering so
        // the lexicographic expiry predicates (GC / recall / touch-fold MAX
        // floors) compare chronologically. Unparseable values pass through
        // byte-for-byte (fail-safe). Also heals a legacy offset rendering on
        // the existing row the first time the row is patched.
        let expires_canon = crate::validate::canonical_valid_time_opt(expires_at);
        let expires_at = expires_canon.as_deref();
        // #2060 — TRACT covenant clause 2: authorship-immutability gate.
        // Consult BEFORE the shadow below so we see the caller's RAW patch
        // metadata (not whatever an upstream `preserve_provenance_keys` call
        // may have already restored to `existing`'s value).
        consult_authorship_immutable_gate(
            existing.metadata.get("agent_id").and_then(|v| v.as_str()),
            metadata,
        )?;
        let metadata = metadata.unwrap_or(&existing.metadata);
        // #3420 (security-high) — reconcile the row's ATTESTATION with the signed
        // envelope this update is about to write. `PUT /memories/{id}` (and the MCP
        // / CLI twins, which all funnel here) can rewrite `title`, `content` and
        // `namespace` — all INSIDE the signed `SignableWrite` envelope — while
        // #3015 preserves `metadata.attest_level` / `metadata.write_signature`
        // across the patch. The combination persisted a row asserting
        // `agent_attested` beside a signature that can never again be re-derived
        // from it: unverifiable by construction, yet believed by every trust
        // surface that reads `attest_level`. The shared entitlement funnel keeps
        // the stored attestation while the envelope is intact, drops it to
        // `claimed` (signature removed) when the envelope is rewritten, and never
        // lets an update MINT one from caller-supplied metadata. `created_at` /
        // `kind` / `agent_id` are not patchable on this in-place funnel, so they
        // are the same on both sides — passed explicitly so the envelope field set
        // is stated in full at the site.
        let existing_agent_id = metadata_agent_id_slot(&existing.metadata).unwrap_or("");
        let attest_entitled = crate::identity::attest::entitled_update_attestation(
            &existing.metadata,
            crate::identity::attest::SignedEnvelopeFields {
                agent_id: existing_agent_id,
                namespace: &existing.namespace,
                title: &existing.title,
                kind: existing.memory_kind.as_str(),
                created_at: &existing.created_at,
                content: &existing.content,
            },
            crate::identity::attest::SignedEnvelopeFields {
                agent_id: existing_agent_id,
                namespace,
                title: new_title,
                kind: existing.memory_kind.as_str(),
                created_at: &existing.created_at,
                content: new_content,
            },
        );
        let attest_reconciled =
            crate::identity::attest::apply_entitled_attestation(metadata, &attest_entitled);
        if attest_reconciled.is_some() {
            tracing::warn!(
                target: "ai_memory::storage::update",
                memory_id = %existing.id,
                downgrade = attest_entitled.is_downgrade_from(&existing.metadata),
                "update reconciled the row's attestation: the persisted \
                 attest_level/write_signature are the substrate-entitled pair for the \
                 post-update signed envelope, not the caller-supplied or stale ones (#3420)"
            );
        }
        let metadata = attest_reconciled.as_ref().unwrap_or(metadata);

        // #1451 (SEC, HIGH) — substrate governance pre-write gate on the
        // optimistic-update path. The insert/supersede/consolidate/restore
        // paths all consult GOVERNANCE_PRE_WRITE; update was the lone gap,
        // so a refuse rule could be evaded by storing benign content then
        // updating it into the refused namespace/tier/title. Build the
        // post-merge row and consult BEFORE any SQL touches the DB; a
        // refusal returns the typed GovernanceRefusal with no row mutated.
        let governed = Memory {
            tier: effective_tier.clone(),
            namespace: namespace.to_string(),
            title: new_title.to_string(),
            content: new_content.to_string(),
            tags: tags.clone(),
            priority,
            confidence,
            expires_at: expires_at.map(str::to_string),
            metadata: metadata.clone(),
            source_uri: source_uri
                .map(str::to_string)
                .or_else(|| existing.source_uri.clone()),
            // v1.0.0 #1834 — reflect the post-merge valid_until for governance
            // (valid_from is carried immutably by the `..existing` spread).
            valid_until: valid_until
                .map(str::to_string)
                .or_else(|| existing.valid_until.clone()),
            ..existing.clone()
        };
        consult_governance_pre_write(&governed)?;
        // #8341 - the ledger projection, read under the write lock (#9405).
        let projected = agent_projection::projected(conn, &governed)?;
        let (new_content, metadata) = projected.as_ref().map_or((new_content, metadata), |p| {
            (p.content.as_str(), &p.metadata)
        });

        let tags_json = serde_json::to_string(tags)?;
        let metadata_json = serde_json::to_string(metadata)?;
        let now = Utc::now().to_rfc3339();

        // #228 Commit B — at-rest content encryption on the in-place update
        // path. Seal the effective NEW content (post-merge) to the per-agent
        // key when enabled; the `content` column then holds the placeholder
        // and `encrypted_envelope` the ciphertext. When disabled (default),
        // `sealed` is None so we write the plaintext verbatim and set the
        // envelope to NULL (clearing any stale ciphertext under encryption-off
        // — byte-identical to the pre-wiring path where the column was always
        // NULL). Both columns are SET together so content + envelope can never
        // desynchronize.
        //
        // v1.0.0 #2383 (N1) — the seal key is the agent id the row will RETAIN,
        // resolved the same way the SQL below resolves it: `json_patch(?10,
        // <existing agent_id/derived_from/consolidated_from_agents>)` overlays
        // the STORED row's provenance on top of the patch (existing-wins,
        // #2106), so a patch that carries a different agent_id — or omits the
        // key entirely — must NOT change which per-agent key the ciphertext is
        // sealed to. Pre-#2383 this read the patch's metadata, so an omitting
        // patch sealed to `""` (a hard fail-closed error on an encrypted
        // deployment) and a differing one produced the #2383 unreadable row.
        let update_agent_id = metadata_agent_id_slot(&existing.metadata)
            .or_else(|| metadata_agent_id_slot(metadata))
            .unwrap_or("");
        let update_sealed = seal_content_guarded(conn, new_content, update_agent_id)?;
        let update_content_to_store = update_sealed
            .as_ref()
            .map_or(new_content, |(_, ph)| ph.as_str());
        let update_encrypted_envelope: Option<&[u8]> =
            update_sealed.as_ref().map(|(env, _)| env.as_slice());

        // Ultrareview #354: rely on the UNIQUE INDEX on (title, namespace)
        // to enforce collision atomically at the DB layer. The previous
        // check-then-update sequence had a race — another transaction
        // could insert a colliding row between the SELECT and the UPDATE,
        // and the UPDATE would surface as a generic SQLite constraint
        // error to the caller. Now the collision check is inline: the
        // UPDATE fails with a well-scoped UniqueViolation, and we re-
        // query the colliding row's id only on that specific error for
        // the friendly message.
        //
        // v0.7.0 Provenance Gap 1 (#884) — UPDATE re-asserts
        // `expected_version` atomically and bumps `version + 1` on
        // success so a racing caller that read the SAME expected_version
        // sees a CONFLICT (their WHERE clause no longer matches the
        // bumped value). When `expected_version` is NULL the
        // `?12 IS NULL` predicate short-circuits the gate.
        // v0.7.0 Provenance Gap 2 (#906) — `source_uri` is an opt-in patch
        // field. When `None`, the COALESCE keeps the stored value (a
        // patch that doesn't touch source_uri must NOT blank it out).
        // When `Some(uri)`, the row's source_uri is rewritten verbatim
        // (rename / scheme migration / bad-data correction).
        // #1725 (v0.8.0) — lossless default update path. The
        // archive-of-prior-content + the in-place UPDATE must run atomically
        // so a mid-failure — or a version-conflict UPDATE that matches 0 rows
        // — rolls BOTH back, leaving the OLD content live (no orphan archive
        // row). The prior content is snapshotted BEFORE the UPDATE overwrites
        // it, under `archive_reason='in_place_edit'` with the SAME memory_id,
        // and ONLY when title/content actually changed (metadata / tag /
        // priority patches don't touch content, so they don't archive).
        //
        // Transaction-aware: some callers already hold an open transaction —
        // the synthesis merge path (`src/mcp/tools/store/synthesis.rs`) wraps
        // candidate updates + provenance rows in ONE `BEGIN IMMEDIATE`. A
        // nested `BEGIN` there fails with "cannot start a transaction within a
        // transaction", so we open our own tx ONLY when none is active
        // (`is_autocommit()` is true only outside a transaction); when the
        // caller owns the tx, the archive + UPDATE run inside it and the
        // caller's commit/rollback covers atomicity. #3152 — that join is what
        // lets a caller fold a lifecycle transition into the SAME transaction.
        connection::in_write_txn(conn, || -> Result<(bool, bool)> {
            if content_changed {
                archive_memory_insert_only(
                    conn,
                    id,
                    crate::models::field_names::ARCHIVE_REASON_IN_PLACE_EDIT,
                )?;
            }
            // #2106 review items 1+2 — preserve the immutable provenance keys
            // (agent_id + the consolidation derived_from / consolidated_from_agents
            // arrays) across the in-place metadata overwrite, mirroring both the
            // `insert` ON CONFLICT arm (#1784) and the postgres
            // `update_with_expected_version_once` CASE overlay so effective
            // protection is IDENTICAL across backends. `json_patch(?10, <existing
            // provenance>)` overlays the OLD row's provenance object on top of the
            // patch (existing-wins) — the bare-column reference `metadata` inside
            // `json_each` resolves to the pre-UPDATE value in a SQLite UPDATE. This
            // closes the omission-erasure hole (#2106 item 2): a full-object
            // metadata patch that OMITS agent_id no longer silently WIPES the
            // stored author — it is preserved (erasure being strictly worse than
            // a rewrite, which the clause-2 gate above already refuses).
            let update_res = conn.execute(
                "UPDATE memories SET tier=?1, namespace=?2, title=?3, content=?4, tags=?5, priority=?6, confidence=?7, updated_at=?8, expires_at=?9,
                    metadata = json_patch(
                        ?10,
                        COALESCE(
                            -- #2941 — same reserved set as the insert funnel: a
                            -- full-object metadata patch that OMITS the pubkey pair
                            -- must not silently unbind the agent's key either.
                            (SELECT json_group_object(key, value)
                             FROM json_each(metadata)
                             WHERE key IN ('agent_id', 'derived_from', 'consolidated_from_agents', 'agent_pubkey', 'pubkey_bound_at')),
                            '{}'
                        )
                    ),
                    source_uri = COALESCE(?11, source_uri), encrypted_envelope=?14, valid_until = COALESCE(?15, valid_until), version = version + 1
                 WHERE id=?12 AND (?13 IS NULL OR version = ?13)",
                params![effective_tier.as_str(), namespace, new_title, update_content_to_store, tags_json, priority, confidence, now, expires_at, metadata_json, source_uri, id, expected_version, update_encrypted_envelope, valid_until],
            );
            match update_res {
                Ok(0) => {
                    // Either the row vanished between SELECT and UPDATE, or
                    // the version drifted (racing writer slipped in). When
                    // expected_version was supplied, re-read so the CONFLICT
                    // envelope carries the current stored value. Returning an
                    // Err here rolls the tx back, reverting the archive so a
                    // version-conflict snapshots nothing.
                    if let Some(expected) = expected_version {
                        let current_version: Option<i64> = conn
                            .query_row(
                                "SELECT version FROM memories WHERE id = ?1",
                                params![id],
                                |r| r.get(0),
                            )
                            .ok();
                        if let Some(current) = current_version {
                            return Err(VersionConflict {
                                id: id.to_string(),
                                expected,
                                current,
                            }
                            .into());
                        }
                    }
                    Ok((false, false))
                }
                Ok(_) => {
                    // APPEND-ONLY-SANCTIONED (#1823 G6) — COW SUPERSEDE: the
                    // in-place UPDATE (same id) is the convergence-proven
                    // path-a supersede. Append ONE identity-only SUPERSEDE leaf
                    // in THIS tx; prior content lives only in the in_place_edit
                    // archive snapshot above, never in the leaf.
                    crate::revisions::emit_revision_leaf_if_enabled(
                        conn,
                        id,
                        crate::revisions::RecordKind::Supersede,
                        expected_version,
                        namespace,
                        Some(update_agent_id).filter(|s| !s.is_empty()),
                        &now,
                    )?;
                    Ok((true, content_changed))
                }
                Err(rusqlite::Error::SqliteFailure(err, message))
                    if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    let other: Option<String> = conn
                        .query_row(
                            "SELECT id FROM memories WHERE title = ?1 AND namespace = ?2 AND id != ?3",
                            params![new_title, namespace, id],
                            |r| r.get(0),
                        )
                        .ok();
                    if let Some(other_id) = other {
                        // #962 typed envelope — UniqueConflict surfaces as
                        // `MemoryError::Conflict` (HTTP 409).
                        return Err(anyhow::Error::new(StorageError::UniqueConflict {
                            reason: format!(
                                "title '{new_title}' already exists in namespace '{namespace}' (memory {other_id})"
                            ),
                        }));
                    }
                    // #8341: keep the SQLite failure as the source so a v102
                    // guard's RAISE(ABORT) message (it names the repair) reaches
                    // the caller instead of being dropped (per ERRORS-11).
                    Err(
                        anyhow::Error::new(rusqlite::Error::SqliteFailure(err, message))
                            .context("update failed with constraint violation"),
                    )
                }
                Err(e) => Err(e.into()),
            }
        })
    })
}
