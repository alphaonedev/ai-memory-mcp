// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8487 — sqlite funnel for the `notify_dedup` table (the sender
//! idempotency key on `memory_notify`). The MCP, CLI and HTTP-sqlite notify
//! and `SqliteStore::notify` all call [`persist_keyed`], so the probe, the
//! quota charge, the inbox insert and the dedup insert have ONE order and ONE
//! failure policy: any error rolls the transaction back, refunds the quota
//! and writes nothing (fail closed; an error is never "not seen").

use super::connection::WriteTxn;
use crate::models::Memory;
use crate::notify_dedup::{DedupVerdict, classify};
use crate::quotas;
use rusqlite::{Connection, OptionalExtension, params};

const SQL_PROBE: &str = "SELECT memory_id, content_digest FROM notify_dedup \
                         WHERE sender = ?1 AND target = ?2 AND key = ?3";
const SQL_INSERT: &str = "INSERT INTO notify_dedup \
                          (sender, target, key, memory_id, content_digest, created_at) \
                          VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
/// Remanence purge (#3192 / #3286): an erased inbox row must not leave its
/// key behind.
pub(crate) const SQL_DELETE_BY_MEMORY_ID: &str = "DELETE FROM notify_dedup WHERE memory_id = ?1";

/// The sender-scoped identity of one keyed delivery and its fingerprint.
#[derive(Debug, Clone, Copy)]
pub struct KeyedDelivery<'a> {
    /// The server-resolved caller.
    pub sender: &'a str,
    /// The recipient agent id.
    pub target: &'a str,
    /// The validated (trimmed) idempotency key.
    pub key: &'a str,
    /// [`crate::notify_dedup::content_digest`] of the delivery.
    pub digest: &'a str,
}

/// How a keyed delivery resolved.
#[derive(Debug)]
pub enum KeyedOutcome {
    /// A new inbox row and its dedup row were committed atomically.
    Inserted(String),
    /// The key was already used with the same content: the original id.
    Hit(String),
}

/// Why a keyed delivery did not resolve.
#[derive(Debug)]
pub enum KeyedError {
    /// The key was used with different content; carries the original id.
    Conflict {
        /// The original inbox row id.
        original_id: String,
    },
    /// The sender's quota refused the delivery.
    Quota(quotas::QuotaCheckError),
    /// A database error; the transaction was rolled back and the quota
    /// refunded.
    Db(anyhow::Error),
}

fn probe(conn: &Connection, d: &KeyedDelivery<'_>) -> rusqlite::Result<DedupVerdict> {
    let found = conn
        .query_row(SQL_PROBE, params![d.sender, d.target, d.key], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .optional()?;
    Ok(classify(found, d.digest))
}

fn refund(conn: &Connection, sender: &str, mem: &Memory, bytes: i64) {
    if let Err(e) = quotas::refund_notify(conn, sender, &mem.namespace, bytes) {
        quotas::log_refund_op_failed(sender, &e);
    }
}

/// Deliver `mem` (an inbox row) under an idempotency key.
///
/// Order: probe (a hit or conflict charges and writes nothing) → quota
/// charge → `BEGIN IMMEDIATE` → re-probe inside the transaction (a concurrent
/// retry that committed first is answered as a hit) → inbox insert → dedup
/// insert → `COMMIT`. A failure after the charge rolls back and refunds.
///
/// # Errors
///
/// [`KeyedError::Conflict`] for a used key with different content,
/// [`KeyedError::Quota`] when the quota refuses, [`KeyedError::Db`] on any
/// probe, insert or commit failure.
pub fn persist_keyed(
    conn: &Connection,
    mem: &Memory,
    d: &KeyedDelivery<'_>,
    payload_bytes: i64,
) -> Result<KeyedOutcome, KeyedError> {
    match probe(conn, d).map_err(|e| KeyedError::Db(e.into()))? {
        DedupVerdict::Hit { id } => return Ok(KeyedOutcome::Hit(id)),
        DedupVerdict::Conflict { id } => return Err(KeyedError::Conflict { original_id: id }),
        DedupVerdict::Miss => {}
    }
    quotas::check_and_record_notify(conn, d.sender, &mem.namespace, payload_bytes)
        .map_err(KeyedError::Quota)?;
    let tx = match WriteTxn::begin(conn) {
        Ok(tx) => tx,
        Err(e) => {
            refund(conn, d.sender, mem, payload_bytes);
            return Err(KeyedError::Db(e.into()));
        }
    };
    let inner = || -> Result<KeyedOutcome, KeyedError> {
        match probe(conn, d).map_err(|e| KeyedError::Db(e.into()))? {
            DedupVerdict::Hit { id } => return Ok(KeyedOutcome::Hit(id)),
            DedupVerdict::Conflict { id } => {
                return Err(KeyedError::Conflict { original_id: id });
            }
            DedupVerdict::Miss => {}
        }
        let id = super::insert_no_overwrite(conn, mem).map_err(KeyedError::Db)?;
        conn.execute(
            SQL_INSERT,
            params![d.sender, d.target, d.key, id, d.digest, mem.created_at],
        )
        .map_err(|e| KeyedError::Db(e.into()))?;
        Ok(KeyedOutcome::Inserted(id))
    };
    match inner() {
        Ok(KeyedOutcome::Inserted(id)) => match tx.commit() {
            Ok(()) => Ok(KeyedOutcome::Inserted(id)),
            Err(e) => {
                refund(conn, d.sender, mem, payload_bytes);
                Err(KeyedError::Db(e.into()))
            }
        },
        other => {
            // A concurrent hit/conflict or a failure: nothing was written by
            // this call, so roll back and give the quota back.
            drop(tx);
            refund(conn, d.sender, mem, payload_bytes);
            other
        }
    }
}
