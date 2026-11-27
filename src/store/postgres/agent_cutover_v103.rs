// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10108 (`3-agent vote (71472661)` V1-AGENT-SIG-SCHEMA, decision A,
//! conditions S-1 and S-3) — the postgres twin of
//! `crate::storage::agent_cutover_v103`: the v103 arm and the whole-table
//! cutover resolver. Both backends build the marker with the SAME
//! [`crate::signed_events::agent_cutover::build_signed_marker`], insert only a
//! [`SignedMarker`], and judge it with the SAME
//! [`crate::signed_events::agent_cutover::resolve_signed`], so a database
//! gives the same verdict on either (#10145 on postgres). Own module for the
//! qual_10 budget of `postgres.rs`.

use super::legacy_cutoff_10074::{PG_ROW_COLUMNS, to_event};
use super::{
    PgSignedEventWalkRow, PostgresStore, TRACE_TARGET, record_schema_version, to_store_err,
    truncate_to_microseconds,
};
use crate::governance::daemon_signer::DaemonChainSigner;
use crate::signed_events::SignedEvent;
use crate::signed_events::agent_cutover::{
    AGENT_CUTOVER_EVENT_TYPE, AGENT_CUTOVER_ROW_LIMIT, AgentCutover, MarkerOrigin, SignedMarker,
    build_signed_marker, legacy_agent_row_count, resolve_signed,
};
use crate::signed_events::agent_era::{AgentDomainEvidence, StoredReceiptRow};
use crate::store::{BoxBackendError, StoreError, StoreResult};

/// The v103 DDL: the two `transcript_line_dedup` columns with their CHECK and
/// the `atomisation_receipts` table (all `IF NOT EXISTS`).
const MIGRATION_V103_AGENT_SIGNATURE_PLACES: &str =
    include_str!("../../../migrations/postgres/0060_v103_agent_signature_places.sql");

/// The row with the highest sequence below `below`.
async fn pg_row_below(
    conn: &mut sqlx::PgConnection,
    below: i64,
    op: &'static str,
) -> StoreResult<Option<SignedEvent>> {
    let row: Option<PgSignedEventWalkRow> = sqlx::query_as(&format!(
        "SELECT {PG_ROW_COLUMNS} FROM signed_events WHERE COALESCE(sequence, 0) < $1 \
         ORDER BY COALESCE(sequence, 0) DESC, id DESC LIMIT 1"
    ))
    .bind(below)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| to_store_err(op, e))?;
    Ok(row.map(to_event))
}

/// The agent-labelled row count below `below` (`None` on a corrupt count).
async fn pg_legacy_agent_rows(
    conn: &mut sqlx::PgConnection,
    below: i64,
    op: &'static str,
) -> StoreResult<Option<u64>> {
    let groups: Vec<(String, i64)> = sqlx::query_as(
        "SELECT attest_level, COUNT(*) FROM signed_events \
         WHERE COALESCE(sequence, 0) < $1 GROUP BY attest_level",
    )
    .bind(below)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| to_store_err(op, e))?;
    Ok(legacy_agent_row_count(
        groups.iter().map(|(a, n)| (a.as_str(), *n)),
    ))
}

/// #10108 — judge the postgres cutover over the WHOLE table, in one
/// `REPEATABLE READ READ ONLY` snapshot (the same shape as the legacy cutoff
/// resolver), whatever window the caller walks. The sqlite twin is
/// [`crate::signed_events::agent_cutover::resolve_sqlite_agent_cutover`]: a
/// marker is judged by [`resolve_signed`] under `verifier` (no key, an
/// unsigned marker or a bad signature is invalid), and no marker is decided
/// by the schema version ([`AgentCutover::without_marker`]), so a removed
/// marker on a v103 database fails the walk (#10145 W-10, W-11).
///
/// # Errors
/// Propagates a pg read error.
pub(super) async fn resolve_pg_agent_cutover(
    pool: &sqlx::PgPool,
    verifier: Option<&ed25519_dalek::VerifyingKey>,
) -> StoreResult<AgentCutover> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| to_store_err("agent_cutover.begin", e))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err("agent_cutover.snapshot", e))?;
    let markers: Vec<PgSignedEventWalkRow> = sqlx::query_as(&format!(
        "SELECT {PG_ROW_COLUMNS} FROM signed_events WHERE event_type = $1 \
         ORDER BY COALESCE(sequence, 0) ASC, id ASC LIMIT $2"
    ))
    .bind(AGENT_CUTOVER_EVENT_TYPE)
    .bind(AGENT_CUTOVER_ROW_LIMIT)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| to_store_err("agent_cutover.rows", e))?;
    let markers: Vec<SignedEvent> = markers.into_iter().map(to_event).collect();
    let verdict = match markers.first() {
        None => {
            let schema_version: Option<i32> =
                sqlx::query_scalar(crate::storage::migrations::SELECT_SCHEMA_VERSION_SQL)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| to_store_err("agent_cutover.schema_version", e))?;
            AgentCutover::without_marker(i64::from(schema_version.unwrap_or(0)))
        }
        Some(first) => {
            let below = first.sequence;
            let prev = pg_row_below(&mut tx, below, "agent_cutover.prev").await?;
            let count = pg_legacy_agent_rows(&mut tx, below, "agent_cutover.count").await?;
            resolve_signed(verifier, &markers, prev.as_ref(), count)
        }
    };
    // Read only: ending the transaction writes nothing.
    tx.rollback()
        .await
        .map_err(|e| to_store_err("agent_cutover.end", e))?;
    Ok(verdict)
}

fn refusal(detail: String) -> StoreError {
    StoreError::Backend(BoxBackendError::new(format!("migrate v103: {detail}")))
}

/// #10108 (lane o) — insert the signed marker. It takes a [`SignedMarker`],
/// which only [`build_signed_marker`] makes, so this writer cannot insert an
/// unsigned or hand-built marker; the signature is bound with the row.
async fn insert_signed_marker(
    conn: &mut sqlx::PgConnection,
    signed: &SignedMarker,
    ts: chrono::DateTime<chrono::Utc>,
) -> StoreResult<i64> {
    let marker = signed.event();
    sqlx::query(
        "INSERT INTO signed_events \
                (id, agent_id, event_type, payload_hash, signature, attest_level, \
                 timestamp, prev_hash, sequence, cause_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL)",
    )
    .bind(&marker.id)
    .bind(&marker.agent_id)
    .bind(&marker.event_type)
    .bind(&marker.payload_hash)
    .bind(&marker.signature)
    .bind(&marker.attest_level)
    .bind(ts)
    .bind(&marker.prev_hash)
    .bind(marker.sequence)
    .execute(&mut *conn)
    .await
    .map_err(|e| to_store_err("v103 insert cutover marker", e))?;
    Ok(marker.sequence)
}

/// v103 (#10108, #10145 on postgres) — the DDL, then the signed cutover marker
/// under `LOCK TABLE signed_events IN EXCLUSIVE MODE`, then the stamp, in ONE
/// transaction: no committed state is at v103 without its marker (S-3). The
/// marker is at sequence 1 above the zero hash on an empty chain (the genesis
/// marker, [`MarkerOrigin::Create`] on a fresh database), else
/// directly above the head; it is skipped only when a marker-type row already
/// exists. The caller provisions `signer` before the ladder starts (K-1), so
/// a missing daemon key refuses before any byte changes.
///
/// # Errors
/// A pg error or a corrupt chain head refuses the step; nothing commits.
pub(super) async fn apply_v103(
    store: &PostgresStore,
    signer: &DaemonChainSigner,
    from_version: i32,
) -> StoreResult<()> {
    // W-9 — a stamp of 0 that reaches the ladder is a fresh database (the
    // #2564 guard in `migrate_locked` refused every other), so its marker says
    // Create and any other says Migrate.
    let origin = if from_version == 0 {
        MarkerOrigin::Create
    } else {
        MarkerOrigin::Migrate
    };
    let mut tx = store
        .pool
        .begin()
        .await
        .map_err(|e| to_store_err("begin v103 tx", e))?;
    sqlx::raw_sql(MIGRATION_V103_AGENT_SIGNATURE_PLACES)
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err("apply v103 agent-signature-places migration", e))?;
    sqlx::query("LOCK TABLE signed_events IN EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err("v103 lock signed_events", e))?;
    let existing: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM signed_events WHERE event_type = $1)")
            .bind(AGENT_CUTOVER_EVENT_TYPE)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| to_store_err("v103 existing marker", e))?;
    let mut written: Option<i64> = None;
    if !existing {
        let head = pg_row_below(&mut tx, i64::MAX, "v103 head").await?;
        // Every row is below the marker: an empty chain counts zero.
        let Some(count) = pg_legacy_agent_rows(&mut tx, i64::MAX, "v103 count").await? else {
            return Err(refusal("corrupt attest_level counts".to_owned()));
        };
        // The signed timestamp is the one postgres reads back (microseconds).
        let ts = truncate_to_microseconds(chrono::Utc::now());
        let Some(signed) = build_signed_marker(
            signer,
            head.as_ref(),
            count,
            origin,
            uuid::Uuid::new_v4().to_string(),
            ts.to_rfc3339(),
        ) else {
            return Err(refusal("no sequence above the chain head".to_owned()));
        };
        written = Some(insert_signed_marker(&mut tx, &signed, ts).await?);
    }
    record_schema_version(&mut tx, 103).await?;
    tx.commit()
        .await
        .map_err(|e| to_store_err("commit v103 migration", e))?;
    tracing::info!(
        target: TRACE_TARGET,
        marker_sequence = ?written,
        "schema migration v103 applied (#10108: agent signature places + cutover marker)"
    );
    Ok(())
}

/// One stored `atomisation_receipts` row, in [`load_pg_agent_evidence`]
/// column order.
type PgReceiptCols = (
    String,
    String,
    String,
    i64,
    String,
    Option<String>,
    Option<Vec<u8>>,
);

/// #10108 (B-4) — the postgres twin of
/// [`crate::signed_events::agent_era::load_sqlite_agent_evidence`]: the
/// receipts and forget tombstones the walk recomputes agent-kind rows from.
/// A missing table is no evidence, never an error (K3 parity).
///
/// # Errors
/// A read of either table failed.
pub(super) async fn load_pg_agent_evidence(
    pool: &sqlx::PgPool,
    daemon_key: Option<&ed25519_dalek::VerifyingKey>,
) -> StoreResult<AgentDomainEvidence> {
    const OP: &str = "verify_audit_trail: agent evidence";
    let (receipts_present, tombstones_present): (bool, bool) = sqlx::query_as(
        "SELECT to_regclass('atomisation_receipts') IS NOT NULL, \
                to_regclass('forget_tombstones') IS NOT NULL",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| to_store_err(OP, e))?;
    let mut receipts = Vec::new();
    if receipts_present {
        let rows: Vec<PgReceiptCols> = sqlx::query_as(
            "SELECT source_id, atomised_at, atom_ids, atom_count, calling_agent_id, \
                    curator_model, signature FROM atomisation_receipts",
        )
        .fetch_all(pool)
        .await
        .map_err(|e| to_store_err(OP, e))?;
        receipts.extend(rows.into_iter().map(|r| StoredReceiptRow {
            source_id: r.0,
            atomised_at: r.1,
            atom_ids_json: r.2,
            atom_count: r.3,
            calling_agent_id: r.4,
            curator_model: r.5,
            signature: r.6,
        }));
    }
    let mut forgotten = Vec::new();
    if tombstones_present {
        let rows: Vec<(String,)> = sqlx::query_as("SELECT memory_id FROM forget_tombstones")
            .fetch_all(pool)
            .await
            .map_err(|e| to_store_err(OP, e))?;
        forgotten.extend(rows.into_iter().map(|(id,)| id));
    }
    Ok(AgentDomainEvidence::build(
        &receipts, &forgotten, daemon_key,
    ))
}
