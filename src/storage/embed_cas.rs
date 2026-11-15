// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #8907 — the vector of a row follows the document bytes of that
//! same row (invariant I-1 of NOTICE-FIX-9284-r1).
//!
//! Two writes keep that invariant by construction, each in ONE statement:
//!
//! * the update funnel's clear compares the old row in SQL (see
//!   `update_with_expected_version`), so a flag computed from a stale
//!   pre-read can never keep a foreign vector;
//! * a re-embed writes its vector with [`write_embedding`] and an
//!   `expected` [`DocumentSnapshot`]: the UPDATE matches only while the row
//!   still holds the exact document bytes the vector was computed from.
//!   Zero rows affected means another writer moved the document on; the
//!   caller reports a degraded receipt and nothing is written, so the other
//!   writer's vector is never erased.
//!
//! The test seam at the bottom lets an integration test commit a second
//! write inside the funnel's pre-read window.

#[cfg(any(test, feature = "test-support"))]
use std::cell::RefCell;

use anyhow::Result;
use rusqlite::{Connection, params};

use super::{EmbeddingDimMismatch, EnvelopeColumn};
use crate::models::Memory;

/// The conditional sibling of `SQL_UPDATE_EMBEDDING_WITH_DIM`: the vector,
/// dim and space land only while the row holds the snapshot's title, content
/// and envelope bytes (`IS` so a NULL envelope compares equal to NULL).
const SQL_UPDATE_EMBEDDING_IF_DOCUMENT: &str = "UPDATE memories SET embedding = ?1, embedding_dim = ?2, embedding_space = ?3 \
     WHERE id = ?4 AND title IS ?5 AND content IS ?6 AND encrypted_envelope IS ?7";

/// The stored document bytes of one row, exactly as the columns hold them
/// (an encrypted row's `content` column and its sealed envelope, never the
/// decrypted text), so a compare against them is a byte compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentSnapshot {
    /// The `title` column.
    pub title: String,
    /// The `content` column (the stored bytes, not the decrypted text).
    pub content: String,
    /// The `encrypted_envelope` column; `None` is SQL NULL.
    pub envelope: Option<Vec<u8>>,
}

/// Map an envelope cell to `Option<bytes>`, failing closed on a non-BLOB.
fn envelope_bytes(row: &rusqlite::Row<'_>) -> rusqlite::Result<Option<Vec<u8>>> {
    match super::read_envelope_column(row, "encrypted_envelope")? {
        EnvelopeColumn::Absent => Ok(None),
        EnvelopeColumn::Blob(bytes) => Ok(Some(bytes)),
        EnvelopeColumn::Malformed(kind) => Err(super::undecryptable_row_error(
            super::malformed_envelope_detail(kind),
        )),
    }
}

/// Row mapper for the update funnel's pre-read: the decrypted row plus its
/// stored envelope bytes, from the SAME row read.
pub(super) fn row_with_envelope(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(Memory, Option<Vec<u8>>)> {
    Ok((super::row_to_memory(row)?, envelope_bytes(row)?))
}

/// Read row `id` ONCE: the decrypted memory (the text to embed) and the
/// stored document bytes it came from. `None` when the row is absent or not
/// recall-visible (the [`super::get`] rule).
///
/// # Errors
/// The SQLite error, or the fail-closed decrypt / malformed-envelope error.
pub fn read_document(conn: &Connection, id: &str) -> Result<Option<(Memory, DocumentSnapshot)>> {
    let mut stmt = conn.prepare_cached(super::SQL_SELECT_MEMORY_ROW_BY_ID)?;
    let mut rows = stmt.query_map(params![id], |row| {
        let memory = super::row_to_memory(row)?;
        let snapshot = DocumentSnapshot {
            title: row.get("title")?,
            content: row.get("content")?,
            envelope: envelope_bytes(row)?,
        };
        Ok((memory, snapshot))
    })?;
    match rows.next() {
        Some(Ok((memory, snapshot))) => Ok(memory
            .lifecycle_state
            .is_recall_visible()
            .then_some((memory, snapshot))),
        Some(Err(e)) => Err(e.into()),
        None => Ok(None),
    }
}

/// The ONE SQLite vector writer (`set_embedding` delegates here). Returns
/// the rows affected.
///
/// * `expected = None`: the unconditional write of a row minted or held
///   under the caller's lock. An empty `embedding` clears the vector to SQL
///   NULL (I-3: "no vector" has one representation).
/// * `expected = Some(snapshot)`: the compare-and-set write of a re-embed.
///   `Ok(0)` means the row no longer holds `snapshot`; nothing is written.
///   An empty vector is refused here: a conditional write that stores no
///   vector has no meaning.
///
/// # Errors
/// The record-stop gate, an empty `space` on a real vector (#3085), an
/// empty vector with `expected`, [`EmbeddingDimMismatch`], or SQLite.
pub fn write_embedding(
    conn: &Connection,
    id: &str,
    embedding: &[f32],
    space: &str,
    expected: Option<&DocumentSnapshot>,
) -> Result<usize> {
    super::record_stop::gate_storage_conn(conn)?;
    let attempted = embedding.len();
    if attempted == 0 {
        if expected.is_some() {
            anyhow::bail!("write_embedding: a conditional write needs a vector (#8907)");
        }
        // The space stamp is NULLed with the (absent) vector.
        return Ok(conn.execute(super::SQL_UPDATE_EMBEDDING_NULL_DIM, params![id])?);
    }
    // #3085 — a REAL vector must carry a REAL space stamp (fail closed).
    super::reject_unattributed_embedding_space("set_embedding", space)?;
    let namespace: Option<String> = conn
        .query_row(
            "SELECT namespace FROM memories WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .ok();
    if let Some(ref ns) = namespace
        && let Some(established) = super::namespace_embedding_dim(conn, ns)?
        && established != attempted
    {
        return Err(EmbeddingDimMismatch {
            namespace: ns.clone(),
            established,
            attempted,
        }
        .into());
    }
    let bytes = crate::embeddings::encode_embedding_blob(embedding);
    let dim_i64 = i64::try_from(attempted).unwrap_or(i64::MAX);
    // #2167 — vector + dim + space stamped atomically in one statement.
    let rows = match expected {
        None => conn.execute(
            super::SQL_UPDATE_EMBEDDING_WITH_DIM,
            params![bytes, dim_i64, space, id],
        )?,
        Some(doc) => conn.execute(
            SQL_UPDATE_EMBEDDING_IF_DOCUMENT,
            params![
                bytes,
                dim_i64,
                space,
                id,
                doc.title,
                doc.content,
                doc.envelope
            ],
        )?,
    };
    Ok(rows)
}

/// A one-shot callback run on the funnel's own connection right after
/// its pre-read: the stand-in for a second writer that commits between
/// the pre-read and the UPDATE.
#[cfg(any(test, feature = "test-support"))]
type AfterPreread = Box<dyn FnOnce(&rusqlite::Connection, &str)>;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static AFTER_PREREAD: RefCell<Option<AfterPreread>> = const { RefCell::new(None) };
}

/// #8907 test seam — arm a one-shot `hook` that the next
/// `update_with_expected_version` on THIS thread runs right after its
/// pre-read, on the same connection, with the row id.
#[cfg(any(test, feature = "test-support"))]
pub fn arm_after_update_preread(hook: impl FnOnce(&rusqlite::Connection, &str) + 'static) {
    AFTER_PREREAD.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// Run the armed pre-read hook once (test builds); a no-op otherwise.
#[cfg(any(test, feature = "test-support"))]
pub(super) fn after_update_preread(conn: &rusqlite::Connection, id: &str) {
    if let Some(hook) = AFTER_PREREAD.with(|slot| slot.borrow_mut().take()) {
        hook(conn, id);
    }
}

/// Run the armed pre-read hook once (test builds); a no-op otherwise.
#[cfg(not(any(test, feature = "test-support")))]
#[inline]
pub(super) fn after_update_preread(_conn: &rusqlite::Connection, _id: &str) {}
