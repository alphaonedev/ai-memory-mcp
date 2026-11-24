// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10074 (S-7, `3-agent vote (71472661) V1-SIGNED-EVENTS-FALLBACK`) — the
//! postgres twin of the sqlite legacy cutoff resolver and operator mint
//! (`crate::signed_events::{resolve_sqlite_legacy_cutoff,
//! mint_legacy_cutoff}`). Both backends validate the cutoff with the SAME
//! [`LegacyCutoffResolver`], so a database gives the same verdict on either.
//! Own module for the qual_10 budget of `postgres.rs`.

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use super::{PgSignedEventWalkRow, PostgresStore, to_store_err, truncate_to_microseconds};
use crate::signed_events::legacy_cutoff::LEGACY_CUTOFF_AGENT_ID;
use crate::signed_events::{
    AnchorDue, ExistingCutoff, LEGACY_CUTOFF_EVENT_TYPE, LegacyCutoff, LegacyCutoffMint,
    LegacyCutoffMintRefusal, LegacyCutoffMinted, LegacyCutoffResolver, MintStep, SignedEvent,
    ZERO_HASH, canonical_chain_bytes, commit_pg_mint, cutoff_row_certifies,
    daemon_row_signing_input, finish_mint, mint_step,
};
use crate::store::StoreResult;

/// The full-row projection, in [`PgSignedEventWalkRow`] order.
const PG_ROW_COLUMNS: &str = "id, agent_id, event_type, payload_hash, signature, attest_level, \
     timestamp, prev_hash, sequence, cause_hash";

/// Map one walk row to a [`SignedEvent`], keeping `prev_hash`.
fn to_event(row: PgSignedEventWalkRow) -> SignedEvent {
    let (id, agent_id, event_type, payload_hash, signature, attest_level, ts, prev, seq, cause) =
        row;
    SignedEvent {
        id,
        agent_id,
        event_type,
        payload_hash,
        signature,
        attest_level,
        timestamp: ts.to_rfc3339(),
        prev_hash: prev,
        sequence: seq,
        cause_hash: cause,
    }
}

/// #10074 (S-2) — resolve the postgres legacy cutoff over the WHOLE table,
/// whatever window the caller walks. Zero, two or more cutoff rows, or one
/// that fails any check, yields [`LegacyCutoff::none`].
///
/// # Errors
/// Propagates a pg read error.
pub(super) async fn resolve_pg_legacy_cutoff(
    pool: &sqlx::PgPool,
    verifier: Option<&VerifyingKey>,
    db_id: Option<&str>,
) -> StoreResult<LegacyCutoff> {
    let cutoffs: Vec<PgSignedEventWalkRow> = sqlx::query_as(&format!(
        "SELECT {PG_ROW_COLUMNS} FROM signed_events WHERE event_type = $1 \
         ORDER BY sequence ASC LIMIT 2"
    ))
    .bind(LEGACY_CUTOFF_EVENT_TYPE)
    .fetch_all(pool)
    .await
    .map_err(|e| to_store_err("legacy_cutoff.rows", e))?;
    // #10107: a second cutoff-type row means no cutoff. The candidate is the
    // lowest-sequence row, the one the sqlite resolver takes, so both
    // backends judge the same row.
    if cutoffs.len() != 1 {
        return Ok(LegacyCutoff::none());
    }
    let Some(cutoff_row) = cutoffs.into_iter().next().map(to_event) else {
        return Ok(LegacyCutoff::none());
    };
    let prefix: Vec<PgSignedEventWalkRow> = sqlx::query_as(&format!(
        "SELECT {PG_ROW_COLUMNS} FROM signed_events \
         WHERE COALESCE(sequence, 0) < $1 ORDER BY COALESCE(sequence, 0) ASC"
    ))
    .bind(cutoff_row.sequence)
    .fetch_all(pool)
    .await
    .map_err(|e| to_store_err("legacy_cutoff.prefix", e))?;
    let mut resolver = LegacyCutoffResolver::new(&cutoff_row, verifier, db_id);
    for row in prefix {
        resolver.feed(&to_event(row));
    }
    Ok(resolver.finish())
}

/// #10104 — the cutoff-type rows of the table (lowest sequence first, at
/// most two) inside the mint transaction, judged by the shared resolver.
async fn pg_existing_cutoff(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    vk: &VerifyingKey,
    db_id: &str,
) -> StoreResult<ExistingCutoff> {
    let cutoffs: Vec<PgSignedEventWalkRow> = sqlx::query_as(&format!(
        "SELECT {PG_ROW_COLUMNS} FROM signed_events WHERE event_type = $1 \
         ORDER BY sequence ASC LIMIT 2"
    ))
    .bind(LEGACY_CUTOFF_EVENT_TYPE)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| to_store_err("mint_legacy_cutoff.cutoff_rows", e))?;
    let row = match <[PgSignedEventWalkRow; 1]>::try_from(cutoffs) {
        Ok([row]) => to_event(row),
        Err(rows) if rows.is_empty() => return Ok(ExistingCutoff::None),
        Err(_) => return Ok(ExistingCutoff::Uncertified),
    };
    let prefix: Vec<PgSignedEventWalkRow> = sqlx::query_as(&format!(
        "SELECT {PG_ROW_COLUMNS} FROM signed_events \
         WHERE COALESCE(sequence, 0) < $1 ORDER BY COALESCE(sequence, 0) ASC"
    ))
    .bind(row.sequence)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| to_store_err("mint_legacy_cutoff.cutoff_prefix", e))?;
    let prefix: Vec<SignedEvent> = prefix.into_iter().map(to_event).collect();
    if cutoff_row_certifies(&row, &prefix, vk, db_id) {
        Ok(ExistingCutoff::Certified(row))
    } else {
        Ok(ExistingCutoff::Uncertified)
    }
}

/// Map a forensic-sink error of the post-commit anchor write.
fn anchor_store_err(e: &anyhow::Error) -> crate::store::StoreError {
    crate::store::StoreError::Backend(crate::store::BoxBackendError::new(format!(
        "mint_legacy_cutoff.anchor: {e:#}"
    )))
}

impl PostgresStore {
    /// #10074 (S-3) — postgres twin of
    /// [`crate::signed_events::mint_legacy_cutoff`]: mint the single legacy
    /// cutoff row under an explicit operator order. One transaction holds an
    /// `EXCLUSIVE` lock on `signed_events` (no append can interleave) and
    /// decides with the shared [`mint_step`]: an untrusted off-table anchor
    /// (#10103), an existing cutoff row with its anchor, an anchor with no
    /// row, an empty or broken chain, or an unverifiable daemon row refuses;
    /// else it appends the cutoff at `head + 1` and COMMITS. Only after the
    /// commit is the anchor written and read back verified (#10104); a crash
    /// between the two leaves a certified row with no anchor, which the next
    /// run repairs (anchor only). Stored rows are never rewritten.
    ///
    /// # Errors
    /// Propagates a pg or forensic-sink error (an open transaction rolls back
    /// on drop). A policy refusal is `Ok(Err(refusal))`.
    pub async fn mint_legacy_cutoff(&self) -> StoreResult<LegacyCutoffMint> {
        use crate::governance::{audit, daemon_signer};
        let Some(vk) = daemon_signer::verifying_key() else {
            return Ok(Err(LegacyCutoffMintRefusal::NoDaemonKey));
        };
        if !audit::is_enabled() {
            return Ok(Err(LegacyCutoffMintRefusal::ForensicSinkDown));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| to_store_err("mint_legacy_cutoff.begin", e))?;
        sqlx::query("LOCK TABLE signed_events IN EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await
            .map_err(|e| to_store_err("mint_legacy_cutoff.lock", e))?;
        let genesis: Option<(String, String, Vec<u8>)> =
            sqlx::query_as(crate::signed_events::GENESIS_ROW_SQL)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| to_store_err("mint_legacy_cutoff.genesis", e))?;
        let Some(db_id) = genesis.map(|(id, agent, ph)| {
            crate::signed_events::db_id_from_genesis_parts(&id, &agent, &ph)
        }) else {
            return Ok(Err(LegacyCutoffMintRefusal::EmptyChain));
        };
        let existing = pg_existing_cutoff(&mut tx, &vk, &db_id).await?;
        match mint_step(&existing, audit::legacy_cutoff_anchor(&db_id, &vk)) {
            Err(refusal) => return Ok(Err(refusal)),
            Ok(MintStep::Repair {
                row_sequence,
                payload_hash_hex,
            }) => {
                // Nothing was written: end the read transaction (its commit
                // writes nothing), then repair.
                let due = AnchorDue {
                    db_id,
                    outcome: LegacyCutoffMinted::AnchorRepaired(row_sequence),
                    payload_hash_hex,
                };
                let committed = commit_pg_mint(tx, due)
                    .await
                    .map_err(|e| to_store_err("mint_legacy_cutoff.commit", e))?;
                return finish_mint(&committed, &vk).map_err(|e| anchor_store_err(&e));
            }
            Ok(MintStep::Mint) => {}
        }
        let rows: Vec<PgSignedEventWalkRow> = sqlx::query_as(&format!(
            "SELECT {PG_ROW_COLUMNS} FROM signed_events ORDER BY COALESCE(sequence, 0) ASC"
        ))
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| to_store_err("mint_legacy_cutoff.walk", e))?;
        let rows: Vec<SignedEvent> = rows.into_iter().map(to_event).collect();
        let Some(head) = rows.last().map(|r| r.sequence) else {
            return Ok(Err(LegacyCutoffMintRefusal::EmptyChain));
        };
        if head < 1 {
            return Ok(Err(LegacyCutoffMintRefusal::EmptyChain));
        }
        // The same structural check the sqlite mint runs through
        // `verify_chain`; the row forms are the resolver's (#10101 / #10102).
        let mut expected_prev = ZERO_HASH.to_vec();
        let mut expected_seq = 1_i64;
        for r in &rows {
            if r.sequence != expected_seq || r.prev_hash != expected_prev {
                return Ok(Err(LegacyCutoffMintRefusal::ChainBreak(r.sequence)));
            }
            expected_prev = Sha256::digest(canonical_chain_bytes(r)).to_vec();
            expected_seq = expected_seq.saturating_add(1);
        }
        let ts = truncate_to_microseconds(chrono::Utc::now());
        let mut row = SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: LEGACY_CUTOFF_AGENT_ID.to_string(),
            event_type: LEGACY_CUTOFF_EVENT_TYPE.to_string(),
            payload_hash: Vec::new(),
            signature: None,
            attest_level: crate::models::AttestLevel::DaemonSigned
                .as_str()
                .to_string(),
            timestamp: ts.to_rfc3339(),
            prev_hash: Vec::new(),
            sequence: head.saturating_add(1),
            cause_hash: None,
        };
        let mut resolver = LegacyCutoffResolver::new(&row, Some(&vk), Some(&db_id));
        for r in &rows {
            resolver.feed(r);
        }
        let (payload_hash, last_hash) = match resolver.mint_payload_hash() {
            Ok(v) => v,
            Err(refusal) => return Ok(Err(refusal.into())),
        };
        row.payload_hash = payload_hash;
        row.prev_hash = last_hash;
        let Some((sig, _)) = daemon_signer::sign(
            daemon_signer::DaemonDomain::LegacyCutoff,
            &daemon_row_signing_input(&row),
        ) else {
            return Ok(Err(LegacyCutoffMintRefusal::NoDaemonKey));
        };
        sqlx::query(
            "INSERT INTO signed_events \
                (id, agent_id, event_type, payload_hash, signature, attest_level, timestamp, \
                 prev_hash, sequence, cause_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL)",
        )
        .bind(&row.id)
        .bind(&row.agent_id)
        .bind(&row.event_type)
        .bind(&row.payload_hash)
        .bind(&sig)
        .bind(&row.attest_level)
        .bind(ts)
        .bind(&row.prev_hash)
        .bind(row.sequence)
        .execute(&mut *tx)
        .await
        .map_err(|e| to_store_err("mint_legacy_cutoff.insert", e))?;
        // #10104 — the row is committed BEFORE the anchor is written.
        let due = AnchorDue {
            db_id,
            outcome: LegacyCutoffMinted::Minted(row.sequence),
            payload_hash_hex: crate::signed_events::hex_lower(&row.payload_hash),
        };
        let committed = commit_pg_mint(tx, due)
            .await
            .map_err(|e| to_store_err("mint_legacy_cutoff.commit", e))?;
        finish_mint(&committed, &vk).map_err(|e| anchor_store_err(&e))
    }
}
