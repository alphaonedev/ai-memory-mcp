// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10028 / #10032 / #10033 — the export boundary refuses a row that is sealed
//! at rest.
//!
//! A memory sealed at rest keeps its content in `encrypted_envelope` (an
//! X25519 + ChaCha20-Poly1305 envelope) with an empty `content` column. No
//! export record format carries that envelope: the convenience format and the
//! Portability v2 `ExportEnvelope` (`spec_version` "2", `deny_unknown_fields`)
//! carry `models::Memory`, which has no envelope field, and the admin
//! `GET /api/v1/export` page carries the same row. Every export reader decrypts
//! the envelope into `Memory::content`, so before this module the artifact held
//! the plaintext and the import wrote it back unsealed (or re-sealed it under a
//! new key, never the same envelope bytes).
//!
//! The invariant (GA standard 1, 3-agent vote 71472661 V3-STD4-SCOPE C-3): a
//! sealed source row is never written as plaintext. An export path that cannot
//! carry the envelope unchanged REFUSES before it writes any byte, with
//! [`SealedExportRefused`], and no flag turns the refusal off. The decision is
//! taken from the row's `encrypted_envelope` column BEFORE any decrypt, so the
//! plaintext is never materialised on the export path at all.
//!
//! Each reader classifies a raw row as [`ExportRow::Plain`] (carrying the
//! projected row) or [`ExportRow::Sealed`] (carrying only the row id, never any
//! content), and pushes it through a [`SealedRowGuard`]. The guard hands a
//! `Plain` row on and counts a `Sealed` one; [`SealedRowGuard::finish`] fails
//! the whole read when any row was sealed. A sealed row therefore has no value
//! that could reach a writer: the `Sealed` arm holds no content to write.

use std::fmt;

/// One exportable row as the reader classified it, before any decrypt.
///
/// `Sealed` carries the row id only: there is no field a plaintext could sit
/// in, so a sealed row cannot be handed to an artifact writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportRow<T> {
    /// The row holds no at-rest envelope; the projection is safe to export.
    Plain(T),
    /// The row holds an at-rest envelope (`encrypted_envelope` is not NULL).
    Sealed {
        /// The row's id, named in the refusal.
        id: String,
    },
}

/// The table names the refusal can name (one place, so the message is stable).
pub mod tables {
    /// The live `memories` table.
    pub const MEMORIES: &str = "memories";
    /// The `archived_memories` table (`export --full`).
    pub const ARCHIVED_MEMORIES: &str = "archived_memories";
}

/// The `encrypted_envelope` column the classification reads.
pub const ENVELOPE_COLUMN: &str = "encrypted_envelope";

/// Collects the sealed rows one export read meets.
#[derive(Debug)]
pub struct SealedRowGuard {
    table: &'static str,
    count: usize,
    first_id: Option<String>,
}

impl SealedRowGuard {
    /// A guard for one read over `table`.
    #[must_use]
    pub fn new(table: &'static str) -> Self {
        Self {
            table,
            count: 0,
            first_id: None,
        }
    }

    /// Hand a plain row on; record a sealed one and return `None`.
    pub fn take<T>(&mut self, row: ExportRow<T>) -> Option<T> {
        match row {
            ExportRow::Plain(v) => Some(v),
            ExportRow::Sealed { id } => {
                self.count = self.count.saturating_add(1);
                if self.first_id.is_none() {
                    self.first_id = Some(id);
                }
                None
            }
        }
    }

    /// `Ok` when the read met no sealed row.
    ///
    /// # Errors
    ///
    /// [`SealedExportRefused`] naming the table, the count and the first id
    /// when any row was sealed.
    pub fn finish(self) -> Result<(), SealedExportRefused> {
        match self.first_id {
            None => Ok(()),
            Some(first_id) => Err(SealedExportRefused {
                table: self.table,
                count: self.count,
                first_id,
            }),
        }
    }
}

/// The export refused because the source holds rows sealed at rest.
///
/// The message names the table, the number of sealed rows and the first row
/// id; it never carries content (the content was never decrypted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedExportRefused {
    /// The table the sealed rows are in.
    pub table: &'static str,
    /// How many rows of the read were sealed.
    pub count: usize,
    /// The id of the first sealed row met.
    pub first_id: String,
}

impl fmt::Display for SealedExportRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{code}: {count} row(s) of {table} are sealed at rest (first id {id}); \
             no export format carries the at-rest envelope, so the export is refused \
             and nothing was written. Move an encrypted store with backup/restore (#10028)",
            code = crate::errors::error_codes::SEALED_EXPORT_REFUSED,
            count = self.count,
            table = self.table,
            id = self.first_id,
        )
    }
}

impl std::error::Error for SealedExportRefused {}

/// Classify a SQLite row by its `encrypted_envelope` column, BEFORE any
/// decrypt; `project` runs only for a row with no envelope.
///
/// # Errors
///
/// The column read or the projection fails.
pub fn classify_sqlite_row<T>(
    row: &rusqlite::Row<'_>,
    project: impl FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> rusqlite::Result<ExportRow<T>> {
    match row.get_ref(ENVELOPE_COLUMN)? {
        rusqlite::types::ValueRef::Null => Ok(ExportRow::Plain(project(row)?)),
        _ => Ok(ExportRow::Sealed { id: row.get("id")? }),
    }
}

/// The scope pre-check of a paged walk: `count` sealed rows in the scope, the
/// least id `first`. A walk refuses on its FIRST page when the scope holds any
/// sealed row, so a client never stores pages of a walk a later page refuses.
///
/// # Errors
///
/// [`SealedExportRefused`] when `count` is above zero. A count that does not
/// fit `usize`, or a positive count with no id, still refuses (fail closed).
pub fn refuse_scope(
    table: &'static str,
    count: i64,
    first: Option<String>,
) -> Result<(), SealedExportRefused> {
    if count <= 0 && first.is_none() {
        return Ok(());
    }
    Err(SealedExportRefused {
        table,
        count: usize::try_from(count).unwrap_or(usize::MAX).max(1),
        first_id: first.unwrap_or_default(),
    })
}

/// Classify a PostgreSQL row by its `encrypted_envelope` column, BEFORE the
/// projection decrypts; `project` runs only for a row with no envelope.
///
/// # Errors
///
/// The column is missing from the row, or the projection fails.
#[cfg(feature = "sal-postgres")]
pub fn classify_pg_row<T>(
    row: &sqlx::postgres::PgRow,
    project: impl FnOnce(&sqlx::postgres::PgRow) -> crate::store::StoreResult<T>,
) -> crate::store::StoreResult<ExportRow<T>> {
    use sqlx::{Row as _, ValueRef as _};
    let raw = row.try_get_raw(ENVELOPE_COLUMN).map_err(|e| {
        crate::store::StoreError::Backend(crate::store::BoxBackendError::new(format!(
            "export envelope column: {e}"
        )))
    })?;
    if raw.is_null() {
        return Ok(ExportRow::Plain(project(row)?));
    }
    let id: String = row.try_get("id").map_err(|e| {
        crate::store::StoreError::Backend(crate::store::BoxBackendError::new(format!(
            "export sealed row id: {e}"
        )))
    })?;
    Ok(ExportRow::Sealed { id })
}

/// The HTTP body of the refusal on both backends: `409` with
/// `{code: SEALED_EXPORT_REFUSED, error}`. The message names a table, a count
/// and a row id, never content.
#[must_use]
pub fn refusal_response(refused: &SealedExportRefused) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    (
        axum::http::StatusCode::CONFLICT,
        axum::Json(serde_json::json!({
            "code": crate::errors::error_codes::SEALED_EXPORT_REFUSED,
            "error": refused.to_string(),
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact message, written out rather than taken from the code.
    const EXPECTED: &str = "SEALED_EXPORT_REFUSED: 2 row(s) of memories are sealed at rest \
        (first id b); no export format carries the at-rest envelope, so the export is refused \
        and nothing was written. Move an encrypted store with backup/restore (#10028)";

    #[test]
    fn guard_passes_plain_rows_and_refuses_on_any_sealed_row_10028() {
        // Every position of one or more sealed rows among plain rows refuses,
        // and a plain-only read passes every row on in order.
        for n in 0..6_usize {
            for mask in 0..(1_u32 << n) {
                let mut g = SealedRowGuard::new(tables::MEMORIES);
                let mut passed = Vec::new();
                let mut sealed = Vec::new();
                for i in 0..n {
                    let row = if mask & (1 << i) == 0 {
                        ExportRow::Plain(i)
                    } else {
                        sealed.push(format!("id-{i}"));
                        ExportRow::Sealed {
                            id: format!("id-{i}"),
                        }
                    };
                    if let Some(v) = g.take(row) {
                        passed.push(v);
                    }
                }
                let plain: Vec<usize> = (0..n).filter(|i| mask & (1 << i) == 0).collect();
                assert_eq!(passed, plain, "n={n} mask={mask:b}");
                match g.finish() {
                    Ok(()) => assert!(sealed.is_empty(), "n={n} mask={mask:b}: sealed passed"),
                    Err(e) => {
                        assert_eq!(e.count, sealed.len(), "n={n} mask={mask:b}");
                        assert_eq!(e.first_id, sealed[0], "n={n} mask={mask:b}");
                        assert_eq!(e.table, tables::MEMORIES);
                    }
                }
            }
        }
    }

    #[test]
    fn refusal_message_is_exact_and_names_no_content_10028() {
        let e = SealedExportRefused {
            table: tables::MEMORIES,
            count: 2,
            first_id: "b".to_string(),
        };
        assert_eq!(e.to_string(), EXPECTED);
    }

    #[test]
    fn scope_precheck_refuses_any_positive_count_10028() {
        assert_eq!(refuse_scope(tables::MEMORIES, 0, None), Ok(()));
        let e = refuse_scope(tables::ARCHIVED_MEMORIES, 3, Some("a".into())).unwrap_err();
        assert_eq!(
            (e.table, e.count, e.first_id.as_str()),
            ("archived_memories", 3, "a")
        );
        // Fail closed on an inconsistent answer: an id with a zero count, or
        // a count with no id, still refuses.
        assert!(refuse_scope(tables::MEMORIES, 0, Some("a".into())).is_err());
        assert!(refuse_scope(tables::MEMORIES, 1, None).is_err());
        assert!(refuse_scope(tables::MEMORIES, i64::MAX, Some("a".into())).is_err());
    }

    #[test]
    fn sqlite_classification_reads_the_column_before_any_decrypt_10028() {
        let conn = rusqlite::Connection::open_in_memory().expect("open");
        conn.execute_batch(
            "CREATE TABLE t (id TEXT, encrypted_envelope BLOB);\
             INSERT INTO t VALUES ('p', NULL), ('s', x'00'), ('e', x'');",
        )
        .expect("seed");
        let mut stmt = conn
            .prepare("SELECT * FROM t ORDER BY rowid")
            .expect("prepare");
        let rows: Vec<ExportRow<String>> = stmt
            .query_map([], |r| {
                // The projection would fail on a sealed row: proving it is
                // never called for one.
                classify_sqlite_row(r, |r| {
                    let id: String = r.get("id")?;
                    assert_eq!(id, "p", "projection ran on a sealed row");
                    Ok(id)
                })
            })
            .expect("query")
            .collect::<rusqlite::Result<_>>()
            .expect("rows");
        assert_eq!(
            rows,
            vec![
                ExportRow::Plain("p".to_string()),
                ExportRow::Sealed { id: "s".into() },
                // An empty, non-NULL envelope is still an envelope.
                ExportRow::Sealed { id: "e".into() },
            ]
        );
    }

    #[test]
    fn refusal_response_is_409_with_the_code_10028() {
        let r = refusal_response(&SealedExportRefused {
            table: tables::MEMORIES,
            count: 1,
            first_id: "x".into(),
        });
        assert_eq!(r.status(), axum::http::StatusCode::CONFLICT);
    }
}
