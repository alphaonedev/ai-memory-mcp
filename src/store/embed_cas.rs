// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #8907 — the compare-and-set vector write of a re-embed, reached
//! through the concrete adapter (`as_any` downcast, the
//! [`super::sqlite::SqliteStore::get_any`] precedent) so the `MemoryStore`
//! trait surface does not change.
//!
//! A store that is neither adapter has no conditional write: the dispatch
//! refuses with a typed error, and the caller reports the write as failed
//! (degrade; never an unconditional vector write).

use super::{MemoryStore, StoreError, StoreResult};
use crate::storage::embed_cas::DocumentSnapshot;

/// The refusal for a store with no compare-and-set vector write.
fn unsupported(op: &str) -> StoreError {
    StoreError::InvalidInput {
        detail: format!("{op}: this store has no conditional vector write (#8907)"),
    }
}

/// The stored document bytes of row `id` (`None` when absent).
///
/// # Errors
/// The adapter's read error, or [`StoreError::InvalidInput`] for a store
/// that is neither adapter.
pub async fn read_document_snapshot(
    store: &dyn MemoryStore,
    id: &str,
) -> StoreResult<Option<DocumentSnapshot>> {
    let any = store.as_any();
    if let Some(sqlite) = any.downcast_ref::<super::sqlite::SqliteStore>() {
        return sqlite.read_document_snapshot(id).await;
    }
    #[cfg(feature = "sal-postgres")]
    if let Some(pg) = any.downcast_ref::<super::postgres::PostgresStore>() {
        return pg.read_document_snapshot(id).await;
    }
    Err(unsupported("read_document_snapshot"))
}

/// ONE conditional statement: the vector lands only while row `id` still
/// holds `expected`. Returns the rows affected (`0` = the document moved on;
/// nothing was written, so no other writer's vector is erased).
///
/// # Errors
/// The adapter's write error, or [`StoreError::InvalidInput`] for a store
/// that is neither adapter.
pub async fn update_embedding_if_document(
    store: &dyn MemoryStore,
    id: &str,
    embedding: &[f32],
    space: &str,
    expected: &DocumentSnapshot,
) -> StoreResult<u64> {
    let any = store.as_any();
    if let Some(sqlite) = any.downcast_ref::<super::sqlite::SqliteStore>() {
        return sqlite
            .update_embedding_if_document(id, embedding, space, expected)
            .await;
    }
    #[cfg(feature = "sal-postgres")]
    if let Some(pg) = any.downcast_ref::<super::postgres::PostgresStore>() {
        return pg
            .update_embedding_if_document(id, embedding, space, expected)
            .await;
    }
    Err(unsupported("update_embedding_if_document"))
}
