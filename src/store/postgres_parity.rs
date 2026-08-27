// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Postgres twins of sqlite-SSOT storage invariants (SAL parity cluster
//! #3174 / #3175 / #3177 / #3180).
//!
//! # Why a sibling module
//!
//! `src/store/postgres.rs` is ~34.5k lines and sits against its QUAL-10
//! module-size ceiling. Every helper here is a *free* function over a
//! `PgPool` / `Transaction`, so it needs nothing from `PostgresStore`'s
//! private state and can live outside that file. The four helpers are the
//! backend twins of storage-layer functions that the postgres adapter had
//! never grown:
//!
//! * [`export_memories_keyset`] — the uncapped admin-export reader
//!   (`crate::storage::export_all` twin) that #3174 needed because the
//!   pg export delegated to `list`, whose `LIST_MAX_LIMIT` clamp silently
//!   truncated a "complete" backup bundle at 1000 rows.
//! * [`evict_tombstone_and_erase_in_tx`] —
//!   [`crate::storage::evict_tombstone_and_erase`] twin (#3177): the
//!   mandatory forget-tombstone + crypto-erase that a TTL/byte-cap
//!   HARD eviction must leave behind so a federated peer cannot resurrect
//!   the evicted row via LWW.
//! * [`archive_links_for_memory_in_tx`] —
//!   `crate::storage::archive_links_for_memory` twin (#3177): the edge
//!   snapshot an ARCHIVING eviction must take before the cascade delete.
//! * [`emit_pending_action_event_in_tx`] —
//!   `crate::storage::emit_pending_action_event` twin (#3180 / #3175): the
//!   governance-decision audit row, with a **byte-identical** canonical
//!   CBOR payload so the two backends commit the same `payload_hash` for
//!   the same decision.

use std::collections::HashSet;

use sqlx::Row;

use crate::models::Memory;
use crate::store::postgres::{
    MEMORY_READ_COLUMNS, PgSignedEventInsert, pg_append_signed_event_with_chain_in_tx, to_store_err,
};
use crate::store::{StoreError, StoreResult};

type PgTx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// Rows fetched per keyset page by [`export_memories_keyset`]. Equal to
/// [`crate::storage::LIST_MAX_LIMIT`] so one page is exactly the window the
/// tenant `list` surface would have returned — the page size is a *pacing*
/// knob (bounded memory + bounded statement time per round-trip), never a
/// cap: the walk continues until the corpus is exhausted.
fn export_page_rows() -> i64 {
    i64::try_from(crate::storage::LIST_MAX_LIMIT).unwrap_or(1_000)
}

/// #3174 — clamp a caller-supplied page limit to
/// [`crate::storage::LIST_MAX_LIMIT`] and **say so** when the clamp actually
/// bites.
///
/// The cap itself is the tenant-facing page cap and stays: raising it would
/// widen every tenant read. What #3174 established is that applying it in
/// SILENCE is the defect — an internal caller that asked for 100_000 rows (the
/// admin export) or 10_000 (the entity-register scan) got a truncated result
/// set with no error, no warning and no truncation flag, so a PARTIAL answer
/// was indistinguishable from a COMPLETE one and shipped as a backup. A caller
/// that genuinely needs the whole set must page (see
/// [`export_memories_keyset`] for the pattern); this WARN is how the next such
/// caller finds out before it ships a lossy read.
///
/// `fallback` is the surface's own documented fallback for the (unreachable in
/// practice — the clamp bounds the value to `LIST_MAX_LIMIT`) `usize -> i64`
/// conversion failure, kept per-surface so this refactor changes no behaviour
/// beyond adding the WARN.
pub(crate) fn clamp_caller_limit(surface: &str, requested: usize, fallback: i64) -> i64 {
    if requested > crate::storage::LIST_MAX_LIMIT {
        tracing::warn!(
            surface,
            requested,
            cap = crate::storage::LIST_MAX_LIMIT,
            "caller limit clamped to LIST_MAX_LIMIT — this result set is TRUNCATED, not complete; page for the full set"
        );
    }
    i64::try_from(requested.clamp(1, crate::storage::LIST_MAX_LIMIT)).unwrap_or(fallback)
}

/// #3174 — UNCAPPED keyset-paged read of the exportable corpus.
///
/// Postgres twin of the sqlite `crate::storage::export_all`
/// (`SELECT * … ORDER BY created_at ASC`, no LIMIT). Applies the SAME two
/// egress predicates as the sqlite reference — the expiry filter and the
/// #1948 fail-closed [`crate::models::lifecycle_visible_clause`]
/// allow-list — and NO visibility filter, matching the admin-export
/// contract (`export_memories` is reachable only from the `require_admin`
/// HTTP route).
///
/// # Why keyset, not OFFSET
///
/// `LIMIT/OFFSET` paging over a moving corpus skips and duplicates rows
/// (a concurrent insert before the cursor shifts every later page). The
/// `(created_at, id)` keyset cursor is a strict total order — `id` is the
/// `TEXT PRIMARY KEY`, so the pair is unique and the walk terminates —
/// and each page resumes exactly after the previous page's last row.
/// `id COLLATE "C"` pins the tiebreak to byte order so the cursor
/// comparison and the `ORDER BY` agree under any server collation (the
/// #1724 lesson: a non-"C" collation makes byte-range predicates drop
/// rows).
///
/// `map_row` is passed as a function pointer so the caller supplies the
/// adapter's own row projection without this module needing access to
/// `PostgresStore`'s private associated functions.
///
/// # Errors
///
/// Propagates the page-query error and any error `map_row` returns.
pub(crate) async fn export_memories_keyset(
    pool: &sqlx::PgPool,
    map_row: fn(&sqlx::postgres::PgRow) -> StoreResult<Option<Memory>>,
) -> StoreResult<Vec<Memory>> {
    let sql = format!(
        "SELECT {cols} FROM memories \
         WHERE (expires_at IS NULL OR expires_at > $4) \
           AND ($1::timestamptz IS NULL \
                OR created_at > $1 \
                OR (created_at = $1 AND id COLLATE \"C\" > $2::text)) \
           {lifecycle_vis} \
         ORDER BY created_at ASC, id COLLATE \"C\" ASC \
         LIMIT $3",
        cols = MEMORY_READ_COLUMNS,
        lifecycle_vis = crate::models::lifecycle_visible_clause(""),
    );
    // The expiry cutoff is captured ONCE and bound to every page, never
    // re-evaluated as `NOW()` per statement. The sqlite reference takes its
    // `now` once for a single one-shot query; a multi-statement walk that let
    // the cutoff drift would apply a DIFFERENT retention boundary to page 1
    // than to page 40, so a row that expired mid-walk would vanish from a
    // bundle whose earlier pages were read under a boundary that included it.
    // One cutoff for the whole walk keeps the bundle internally consistent.
    let as_of = chrono::Utc::now();
    let page_rows = export_page_rows();
    let mut out: Vec<Memory> = Vec::new();
    let mut cursor: Option<(chrono::DateTime<chrono::Utc>, String)> = None;
    let mut skipped = 0_usize;
    loop {
        let rows = sqlx::query(&sql)
            .bind(cursor.as_ref().map(|(ts, _)| *ts))
            .bind(cursor.as_ref().map(|(_, id)| id.as_str()))
            .bind(page_rows)
            .bind(as_of)
            .fetch_all(pool)
            .await
            .map_err(|e| to_store_err("export_memories keyset page", e))?;
        let Some(last) = rows.last() else {
            break;
        };
        // Advance the cursor from the RAW last row BEFORE projection: a row
        // the projection skips (undecryptable under the #2383 discovery-scan
        // policy) must still move the cursor, or the walk would re-fetch the
        // same page forever.
        let last_created: chrono::DateTime<chrono::Utc> = last
            .try_get(crate::models::field_names::CREATED_AT)
            .map_err(|e| to_store_err("export_memories cursor created_at", e))?;
        let last_id: String = last
            .try_get("id")
            .map_err(|e| to_store_err("export_memories cursor id", e))?;
        cursor = Some((last_created, last_id));
        let page_len = rows.len();
        for r in &rows {
            match map_row(r)? {
                Some(m) => out.push(m),
                None => skipped += 1,
            }
        }
        if i64::try_from(page_len).unwrap_or(i64::MAX) < page_rows {
            break;
        }
    }
    if skipped > 0 {
        // Honesty over silence: the bundle is INCOMPLETE by exactly this many
        // rows. The projection's skip-row policy is deliberate (one
        // undecryptable row must not deny the whole scan), but an export that
        // drops rows without saying so is the #3174 defect class.
        tracing::warn!(
            skipped,
            exported = out.len(),
            "export_memories: skipped undecryptable rows — the bundle is NOT the full corpus"
        );
    }
    Ok(out)
}

/// #3177 / #1956 [R56] — postgres twin of
/// [`crate::storage::evict_tombstone_and_erase`].
///
/// Runs INSIDE the caller's transaction, BEFORE the eviction `DELETE`, so
/// the erase + attestation + tombstone + delete commit or roll back as one
/// unit. For each victim it:
///
/// 1. **crypto-erases** the per-record (`0x03`) envelope key, making the
///    ciphertext unrecoverable even by a holder of the master KEK. Legacy
///    `0x02` per-agent rows have no per-record key — the honest limit,
///    recorded as `RowDeletedTombstoned` rather than `KeyDestroyed`.
/// 2. **scrubs the `cid_genesis` pre-image** (erasure invariant parity with
///    `forget`).
/// 3. appends a signed `substrate.crypto_erase` **erasure attestation**
///    committing `{id, erasure-kind, actor, timestamp}`.
/// 4. inserts the mandatory signed **forget tombstone** — the federation
///    resurrection guard. Without it, `apply_remote_memory` on this node
///    accepts a peer's copy of the evicted row back via LWW while the
///    sqlite twin refuses it.
///
/// Deliberately **ungated** by `append_only_enabled()`: the revision leaf
/// is an optional ledger, the tombstone + erase is the retention contract.
/// The sqlite twin is likewise unconditional.
///
/// `victims` is `(id, namespace, metadata.agent_id)`; an empty slice is a
/// no-op. Idempotent — the tombstone insert is `ON CONFLICT DO NOTHING`.
///
/// # Errors
///
/// Propagates the crypto-erase / scrub / attestation-append / tombstone
/// insert error.
pub(crate) async fn evict_tombstone_and_erase_in_tx(
    tx: &mut PgTx<'_>,
    victims: &[(String, String, Option<String>)],
    now: chrono::DateTime<chrono::Utc>,
) -> StoreResult<()> {
    if victims.is_empty() {
        return Ok(());
    }
    let ids: Vec<String> = victims.iter().map(|(id, _, _)| id.clone()).collect();

    // (1) Crypto-erase the per-record envelope keys. `get_byte(...,0) = 3`
    // selects ONLY the per-record scheme (mirrors the `forget` twin).
    // RETURNING id so each victim's erasure KIND is known below.
    let erased_rows: Vec<(String,)> = sqlx::query_as(
        "UPDATE memories SET encrypted_envelope = $2 \
         WHERE id = ANY($1) \
           AND encrypted_envelope IS NOT NULL \
           AND get_byte(encrypted_envelope, 0) = 3 \
         RETURNING id",
    )
    .bind(&ids)
    .bind(crate::encryption::crypto_erase_marker())
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| to_store_err("evict crypto-erase envelope", e))?;
    let erased: HashSet<String> = erased_rows.into_iter().map(|(id,)| id).collect();

    // (2) Erasure invariant — scrub the cid pre-image (parity with forget).
    sqlx::query(
        "UPDATE memories SET cid_genesis = NULL WHERE cid_genesis IS NOT NULL AND id = ANY($1)",
    )
    .bind(&ids)
    .execute(&mut **tx)
    .await
    .map_err(|e| to_store_err("evict scrub cid_genesis", e))?;

    // (3) Signed erasure attestation per victim.
    let ts = now.to_rfc3339();
    for (id, _ns, agent) in victims {
        let kind = if erased.contains(id) {
            crate::storage::ErasureKind::KeyDestroyed
        } else {
            crate::storage::ErasureKind::RowDeletedTombstoned
        };
        let actor = agent
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(crate::storage::CRYPTO_ERASE_ACTOR_SUBSTRATE);
        let signable = crate::storage::crypto_erase_signable_bytes(id, kind, actor, &ts);
        let event = crate::signed_events::SignedEvent::with_daemon_signature(
            crate::signed_events::payload_hash(&signable),
            actor.to_string(),
            crate::signed_events::event_types::SUBSTRATE_CRYPTO_ERASE.to_string(),
            ts.clone(),
            None,
        );
        pg_append_signed_event_with_chain_in_tx(
            tx,
            PgSignedEventInsert {
                id: &event.id,
                agent_id: &event.agent_id,
                event_type: &event.event_type,
                payload_hash: &event.payload_hash,
                signature: event.signature.as_deref(),
                attest_level: &event.attest_level,
                timestamp: now,
                cause_hash: None,
            },
        )
        .await
        .map_err(|e| to_store_err("evict crypto_erase attestation", e))?;
    }

    // (4) Mandatory signed tombstone — identity + time + owner ONLY, never
    // content. Bulk UNNEST insert (parity with the `forget` twin).
    let namespaces: Vec<String> = victims.iter().map(|(_, ns, _)| ns.clone()).collect();
    let agents: Vec<Option<String>> = victims.iter().map(|(_, _, a)| a.clone()).collect();
    let forgotten: Vec<String> = vec![ts.clone(); victims.len()];
    let signatures: Vec<Option<Vec<u8>>> = victims
        .iter()
        .map(|(id, ns, _)| {
            let signable = crate::storage::forget_tombstone_signable_bytes(id, ns, &ts);
            crate::governance::audit::try_sign_audit_payload(&signable).map(|(s, _)| s)
        })
        .collect();
    sqlx::query(
        "INSERT INTO forget_tombstones \
             (memory_id, namespace, forgotten_at, agent_id, signature) \
         SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::bytea[]) \
         ON CONFLICT (memory_id) DO NOTHING",
    )
    .bind(&ids)
    .bind(&namespaces)
    .bind(&forgotten)
    .bind(&agents)
    .bind(&signatures)
    .execute(&mut **tx)
    .await
    .map_err(|e| to_store_err("evict record tombstones", e))?;

    Ok(())
}

/// #3177 / #1771 — postgres twin of
/// `crate::storage::archive_links_for_memory`: snapshot one memory's
/// `memory_links` into `archived_memory_links` BEFORE the same-tx cascade
/// `DELETE` reaps them (FK `ON DELETE CASCADE`), so `archive_restore` can
/// re-insert the edge graph. Idempotent via the PK `ON CONFLICT`.
///
/// Identical statement to the one `archive_by_ids` already runs — hoisted
/// here so the eviction archive path (`size_gc(archive = true)`) reuses it
/// instead of leaving an archived row with no edges.
///
/// # Errors
///
/// Propagates the snapshot-insert error.
pub(crate) async fn archive_links_for_memory_in_tx(tx: &mut PgTx<'_>, id: &str) -> StoreResult<()> {
    sqlx::query(
        "INSERT INTO archived_memory_links (
             source_id, target_id, relation, created_at, valid_from,
             valid_until, observed_by, signature, attest_level, archived_at
         )
         SELECT ml.source_id, ml.target_id, ml.relation, ml.created_at,
                ml.valid_from, ml.valid_until, ml.observed_by,
                ml.signature, ml.attest_level, now()
         FROM memory_links ml
         WHERE ml.source_id = $1 OR ml.target_id = $1
         ON CONFLICT (source_id, target_id, relation) DO NOTHING",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(|e| to_store_err("archive links for memory", e))?;
    Ok(())
}

/// #3180 / #3175 (v0.7.0 S5-M1/M2/H4) — postgres twin of
/// `crate::storage::emit_pending_action_event`: append a
/// `pending_action.<state>` row to the signed-events chain so a governance
/// decision transition is provable.
///
/// `event_type` is one of `pending_action.approved` /
/// `pending_action.denied` / `pending_action.refused_agent_id_mismatch`
/// (the timeout emit stays on the sqlite sweeper — see the #3180 residual
/// note in the PR).
///
/// # Canonical-payload parity
///
/// The CBOR map is built key-sorted through a [`std::collections::BTreeMap`]
/// over the SAME seven fields, in the SAME order, with the SAME
/// `field_names` constants as the sqlite writer, and hashed with the SAME
/// [`crate::signed_events::payload_hash`]. So for one decision the two
/// backends commit a byte-identical `payload_hash` — an auditor comparing a
/// sqlite and a postgres node's chains sees the same commitment, and the
/// parity is provable by assertion rather than inspection.
///
/// Unlike the sqlite twin (which is best-effort/warn-only on a bare
/// `Connection`), this runs inside the caller's transaction: the postgres
/// chain append MUST be transactional to compute `sequence`/`prev_hash`
/// atomically. Callers choose the disposition — `pending_decide` propagates
/// (fail closed: no unaudited deny), the post-execute `approved` emit warns.
///
/// # Errors
///
/// Returns [`StoreError::IntegrityFailed`] if the canonical CBOR cannot be
/// encoded, else propagates the chain-append error.
pub(crate) async fn emit_pending_action_event_in_tx(
    tx: &mut PgTx<'_>,
    pa: &crate::models::PendingAction,
    event_type: &str,
    decided_by_override: Option<&str>,
) -> StoreResult<()> {
    use crate::models::field_names;
    use std::collections::BTreeMap;

    let decided_by = decided_by_override
        .map(str::to_string)
        .or_else(|| pa.decided_by.clone())
        .unwrap_or_default();
    let now = chrono::Utc::now();
    let timestamp = now.to_rfc3339();
    let mut map: BTreeMap<&str, ciborium::Value> = BTreeMap::new();
    map.insert(
        field_names::PENDING_ID,
        ciborium::Value::Text(pa.id.clone()),
    );
    map.insert(
        field_names::ACTION_TYPE,
        ciborium::Value::Text(pa.action_type.clone()),
    );
    map.insert("namespace", ciborium::Value::Text(pa.namespace.clone()));
    map.insert(
        field_names::REQUESTED_BY,
        ciborium::Value::Text(pa.requested_by.clone()),
    );
    map.insert(
        field_names::DECIDED_BY,
        ciborium::Value::Text(decided_by.clone()),
    );
    map.insert("status", ciborium::Value::Text(pa.status.clone()));
    map.insert("timestamp", ciborium::Value::Text(timestamp.clone()));
    let entries: Vec<(ciborium::Value, ciborium::Value)> = map
        .into_iter()
        .map(|(k, v)| (ciborium::Value::Text(k.to_string()), v))
        .collect();
    let mut cbor: Vec<u8> = Vec::with_capacity(128);
    ciborium::ser::into_writer(&ciborium::Value::Map(entries), &mut cbor).map_err(|e| {
        StoreError::IntegrityFailed {
            detail: format!("encode canonical CBOR for {event_type}: {e}"),
        }
    })?;

    // The audit row's `agent_id` is the decision ACTOR. (The sqlite twin
    // additionally maps the requester-less `pending_action.timed_out` path to
    // the requester; that emit has no postgres caller yet.)
    let event = crate::signed_events::SignedEvent::with_daemon_signature(
        crate::signed_events::payload_hash(&cbor),
        decided_by,
        event_type.to_string(),
        timestamp,
        None,
    );
    pg_append_signed_event_with_chain_in_tx(
        tx,
        PgSignedEventInsert {
            id: &event.id,
            agent_id: &event.agent_id,
            event_type: &event.event_type,
            payload_hash: &event.payload_hash,
            signature: event.signature.as_deref(),
            attest_level: &event.attest_level,
            timestamp: now,
            cause_hash: None,
        },
    )
    .await
    .map_err(|e| to_store_err("append pending_action audit row", e))?;
    Ok(())
}
