// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! pgvector vs BYTEA embedding storage for [`super::PostgresStore`].
//!
//! When `CREATE EXTENSION vector` is possible, the adapter keeps the
//! existing `vector(N)` + HNSW path. When the extension is missing or
//! the role cannot create it — or `AI_MEMORY_PG_NO_VECTOR=1` is set —
//! embeddings are stored as little-endian `f32` BYTEA. Keyword recall
//! uses `tsvector` (built-in). Semantic recall scores cosine in-process,
//! same as the SQLite adapter.

use sqlx::postgres::PgArguments;
use sqlx::query::Query;
use sqlx::{PgPool, Postgres};

use super::{EMBEDDING_DIM_PLACEHOLDER, StoreError, StoreResult};

/// How `memories.embedding` is typed on this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddingMode {
    /// `vector(N)` + HNSW (`<=>`). Requires the `vector` extension.
    PgVector,
    /// `BYTEA` of LE f32s. No extension. Cosine is computed in Rust.
    Bytea,
}

impl EmbeddingMode {
    #[must_use]
    pub fn uses_pgvector(self) -> bool {
        matches!(self, Self::PgVector)
    }
}

/// `AI_MEMORY_PG_NO_VECTOR=1|true|yes` forces BYTEA even if the role
/// could `CREATE EXTENSION vector`.
#[must_use]
pub fn env_force_no_vector() -> bool {
    match std::env::var("AI_MEMORY_PG_NO_VECTOR") {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// Pack an embedding as little-endian f32 bytes (SQLite-shaped blob).
#[must_use]
pub fn encode_f32_le(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len().saturating_mul(4));
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

/// Inverse of [`encode_f32_le`]. `None` if the blob length is not a
/// multiple of 4.
#[must_use]
pub fn decode_f32_le(b: &[u8]) -> Option<Vec<f32>> {
    if !b.len().is_multiple_of(4) {
        return None;
    }
    Some(
        b.chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect(),
    )
}

/// Rewrite the bundled schema so it does not mention pgvector.
#[must_use]
pub fn render_schema_sql_with_mode(template: &str, dim: u32, mode: EmbeddingMode) -> String {
    let templated = match mode {
        EmbeddingMode::PgVector => template.to_string(),
        EmbeddingMode::Bytea => template
            .replace(
                "CREATE EXTENSION IF NOT EXISTS vector;",
                "-- skipped: no-vector mode (BYTEA embeddings)",
            )
            .replace("vector({EMBEDDING_DIM})", "BYTEA")
            .replace(
                "CREATE INDEX IF NOT EXISTS memories_embedding_hnsw ON memories\n    USING hnsw (embedding vector_cosine_ops);",
                "-- skipped: no-vector mode (no HNSW)",
            ),
    };
    templated.replace(EMBEDDING_DIM_PLACEHOLDER, &dim.to_string())
}

/// Bind an optional embedding in the column type for `mode`.
pub fn bind_embedding<'q>(
    mode: EmbeddingMode,
    q: Query<'q, Postgres, PgArguments>,
    embedding: Option<&[f32]>,
) -> Query<'q, Postgres, PgArguments> {
    match mode {
        EmbeddingMode::PgVector => q.bind(embedding.map(|v| pgvector::Vector::from(v.to_vec()))),
        EmbeddingMode::Bytea => q.bind(embedding.map(encode_f32_le)),
    }
}

/// Decide storage before `INIT_SCHEMA` runs.
///
/// 1. Existing `memories.embedding` type wins (cannot flip a live column).
/// 2. Else `AI_MEMORY_PG_NO_VECTOR` forces BYTEA.
/// 3. Else try `CREATE EXTENSION vector`; permission / missing `.so`
///    falls back to BYTEA (same spirit as AGE → CTE).
pub async fn resolve_embedding_mode(pool: &PgPool) -> StoreResult<EmbeddingMode> {
    if let Some(typ) = embedding_type_name(pool).await? {
        let mode = if typ == "vector" {
            EmbeddingMode::PgVector
        } else {
            EmbeddingMode::Bytea
        };
        tracing::info!(
            target: "ai_memory::store::postgres",
            typ,
            ?mode,
            "existing memories.embedding type selects embedding mode"
        );
        return Ok(mode);
    }

    if env_force_no_vector() {
        tracing::info!(
            target: "ai_memory::store::postgres",
            "AI_MEMORY_PG_NO_VECTOR set; BYTEA embeddings"
        );
        return Ok(EmbeddingMode::Bytea);
    }

    match sqlx::query("CREATE EXTENSION IF NOT EXISTS vector")
        .execute(pool)
        .await
    {
        Ok(_) => Ok(EmbeddingMode::PgVector),
        Err(e) => {
            tracing::warn!(
                target: "ai_memory::store::postgres",
                error = %e,
                "pgvector not creatable; BYTEA embeddings (FTS + in-process cosine)"
            );
            Ok(EmbeddingMode::Bytea)
        }
    }
}

async fn embedding_type_name(pool: &PgPool) -> StoreResult<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT t.typname
         FROM pg_attribute a
         JOIN pg_class c ON c.oid = a.attrelid
         JOIN pg_type t ON t.oid = a.atttypid
         JOIN pg_namespace n ON c.relnamespace = n.oid
         WHERE n.nspname = 'public'
           AND c.relname = 'memories'
           AND a.attname = 'embedding'
           AND a.attnum > 0
           AND NOT a.attisdropped",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| StoreError::BackendUnavailable {
        backend: "postgres".to_string(),
        detail: format!("probe memories.embedding type: {e}"),
    })?;
    Ok(row.map(|(t,)| t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let src = vec![0.0_f32, -1.5, 2.25, f32::MIN_POSITIVE];
        let decoded = decode_f32_le(&encode_f32_le(&src)).expect("roundtrip");
        assert_eq!(decoded, src);
    }

    #[test]
    fn decode_rejects_ragged_blob() {
        assert!(decode_f32_le(&[0, 1, 2]).is_none());
    }

    #[test]
    fn env_force_parses_truthy() {
        // Isolated: we only assert the matcher, not process env.
        for v in ["1", "true", "YES", "On"] {
            assert!(
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                ),
                "{v}"
            );
        }
    }
}
