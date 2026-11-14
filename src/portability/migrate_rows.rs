// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8888 — the row classes `migrate` used to drop: archived rows (the
//! `archived_memories` table) and expired rows GC has not swept yet.
//!
//! This module holds the backend-neutral decode of one archived row (the JSON
//! shape `MemoryStore::list_archived` returns on BOTH adapters) and the sqlite
//! primitives the `SqliteStore` SAL methods delegate to. The Postgres twins
//! live on `PostgresStore` and consume the same [`ArchivedRowFields`] decode,
//! so the two backends cannot drift on which keys are required.

use anyhow::{Context, Result, anyhow};
use rusqlite::{Connection, params};
use serde_json::Value;

use crate::models::{Memory, field_names};

/// The JSON keys of a `list_archived` row that MUST be present and typed.
/// A missing one is a refusal, never a defaulted column (#1080 posture).
pub const REQUIRED_ARCHIVED_KEYS: &[&str] = &[
    "id",
    "tier",
    "namespace",
    "title",
    "content",
    "priority",
    field_names::CREATED_AT,
    field_names::UPDATED_AT,
    field_names::ARCHIVED_AT,
    field_names::ARCHIVE_REASON,
];

/// One archived row decoded from the `list_archived` JSON shape. JSON-valued
/// columns are carried as their serialized text so each backend binds them
/// as its own column type (`TEXT` on sqlite, `JSONB` / `TEXT` on Postgres).
#[derive(Debug, Clone, PartialEq)]
pub struct ArchivedRowFields {
    pub id: String,
    pub tier: String,
    pub namespace: String,
    pub title: String,
    pub content: String,
    pub tags_json: String,
    pub priority: i64,
    pub confidence: f64,
    pub source: String,
    pub access_count: i64,
    pub created_at: String,
    pub updated_at: String,
    pub last_accessed_at: Option<String>,
    pub expires_at: Option<String>,
    pub archived_at: String,
    pub archive_reason: String,
    pub metadata_json: String,
    pub reflection_depth: Option<i64>,
    pub memory_kind: Option<String>,
    pub entity_id: Option<String>,
    pub persona_version: Option<i64>,
    pub citations_json: Option<String>,
    pub source_uri: Option<String>,
    pub source_span_json: Option<String>,
    pub confidence_source: Option<String>,
    pub confidence_signals_json: Option<String>,
    pub confidence_decayed_at: Option<String>,
    pub version: Option<i64>,
    pub atomised_into: Option<i64>,
    pub atom_of: Option<String>,
    pub mentioned_entity_id: Option<String>,
}

fn required_str(row: &Value, key: &str) -> Result<String> {
    row.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("archived row: required key `{key}` is missing or not a string"))
}

fn optional_str(row: &Value, key: &str) -> Result<Option<String>> {
    match row.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(anyhow!("archived row: key `{key}` is not a string")),
    }
}

fn optional_i64(row: &Value, key: &str) -> Result<Option<i64>> {
    match row.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .map(Some)
            .ok_or_else(|| anyhow!("archived row: key `{key}` is not an integer")),
    }
}

/// A JSON-valued column, serialized back to text; `null` / absent is `None`.
fn optional_json_text(row: &Value, key: &str) -> Result<Option<String>> {
    match row.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => serde_json::to_string(v)
            .map(Some)
            .with_context(|| format!("archived row: re-serialize `{key}`")),
    }
}

impl ArchivedRowFields {
    /// Decode one `list_archived` row.
    ///
    /// # Errors
    ///
    /// A required key (see [`REQUIRED_ARCHIVED_KEYS`]) missing or mistyped,
    /// or an optional key of the wrong JSON type.
    pub fn from_json(row: &Value) -> Result<Self> {
        let priority = row
            .get("priority")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("archived row: required key `priority` is not an integer"))?;
        let tags_json = match row.get("tags") {
            None | Some(Value::Null) => "[]".to_string(),
            Some(v) => serde_json::to_string(v).context("archived row: re-serialize `tags`")?,
        };
        let metadata_json = match row.get("metadata") {
            None | Some(Value::Null) => "{}".to_string(),
            Some(v) => serde_json::to_string(v).context("archived row: re-serialize `metadata`")?,
        };
        Ok(Self {
            id: required_str(row, "id")?,
            tier: required_str(row, "tier")?,
            namespace: required_str(row, "namespace")?,
            title: required_str(row, "title")?,
            content: required_str(row, "content")?,
            tags_json,
            priority,
            confidence: row
                .get(field_names::CONFIDENCE)
                .and_then(Value::as_f64)
                .unwrap_or(1.0),
            source: optional_str(row, "source")?.unwrap_or_else(|| "import".to_string()),
            access_count: optional_i64(row, field_names::ACCESS_COUNT)?.unwrap_or(0),
            created_at: required_str(row, field_names::CREATED_AT)?,
            updated_at: required_str(row, field_names::UPDATED_AT)?,
            last_accessed_at: optional_str(row, field_names::LAST_ACCESSED_AT)?,
            expires_at: optional_str(row, field_names::EXPIRES_AT)?,
            archived_at: required_str(row, field_names::ARCHIVED_AT)?,
            archive_reason: required_str(row, field_names::ARCHIVE_REASON)?,
            metadata_json,
            reflection_depth: optional_i64(row, field_names::REFLECTION_DEPTH)?,
            memory_kind: optional_str(row, field_names::MEMORY_KIND)?,
            entity_id: optional_str(row, "entity_id")?,
            persona_version: optional_i64(row, field_names::PERSONA_VERSION)?,
            citations_json: optional_json_text(row, "citations")?,
            source_uri: optional_str(row, field_names::SOURCE_URI)?,
            source_span_json: optional_json_text(row, field_names::SOURCE_SPAN)?,
            confidence_source: optional_str(row, field_names::CONFIDENCE_SOURCE)?,
            confidence_signals_json: optional_json_text(row, field_names::CONFIDENCE_SIGNALS)?,
            confidence_decayed_at: optional_str(row, field_names::CONFIDENCE_DECAYED_AT)?,
            version: optional_i64(row, "version")?,
            atomised_into: optional_i64(row, field_names::ATOMISED_INTO)?,
            atom_of: optional_str(row, field_names::ATOM_OF)?,
            mentioned_entity_id: optional_str(row, field_names::MENTIONED_ENTITY_ID)?,
        })
    }
}

/// Insert one archived row if its id is absent. `Ok(true)` = written.
///
/// # Errors
///
/// A decode refusal from [`ArchivedRowFields::from_json`] or the SQLite error.
pub fn sqlite_insert_archived_row(conn: &Connection, row: &Value) -> Result<bool> {
    let f = ArchivedRowFields::from_json(row)?;
    let n = conn
        .execute(
            "INSERT OR IGNORE INTO archived_memories \
                (id, tier, namespace, title, content, tags, priority, confidence, \
                 source, access_count, created_at, updated_at, last_accessed_at, \
                 expires_at, archived_at, archive_reason, metadata, reflection_depth, \
                 memory_kind, entity_id, persona_version, citations, source_uri, \
                 source_span, confidence_source, confidence_signals, \
                 confidence_decayed_at, version, atomised_into, atom_of, \
                 mentioned_entity_id) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18, \
                     ?19,?20,?21,?22,?23,?24,?25,?26,?27,COALESCE(?28, 1),?29,?30,?31)",
            params![
                f.id,
                f.tier,
                f.namespace,
                f.title,
                f.content,
                f.tags_json,
                f.priority,
                f.confidence,
                f.source,
                f.access_count,
                f.created_at,
                f.updated_at,
                f.last_accessed_at,
                f.expires_at,
                f.archived_at,
                f.archive_reason,
                f.metadata_json,
                f.reflection_depth.unwrap_or(0),
                f.memory_kind,
                f.entity_id,
                f.persona_version,
                f.citations_json,
                f.source_uri,
                f.source_span_json,
                f.confidence_source,
                f.confidence_signals_json,
                f.confidence_decayed_at,
                f.version,
                f.atomised_into,
                f.atom_of,
                f.mentioned_entity_id,
            ],
        )
        .with_context(|| format!("insert archived row {}", f.id))?;
    Ok(n == 1)
}

/// One page of the expired-but-unswept rows, `created_at ASC, id ASC`.
/// `limit` is clamped to `storage::LIST_MAX_LIMIT`, like `list`.
///
/// # Errors
///
/// The SQLite error, or a row that does not map (fail closed: an
/// undecryptable row is an error, never a silent skip).
pub fn sqlite_list_expired_unswept(
    conn: &Connection,
    namespace: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<Vec<Memory>> {
    let now = chrono::Utc::now().to_rfc3339();
    let limit = i64::try_from(limit.clamp(1, crate::storage::LIST_MAX_LIMIT))
        .context("expired page limit")?;
    let offset = i64::try_from(offset).context("expired page offset")?;
    let sql = format!(
        "SELECT * FROM memories WHERE expires_at IS NOT NULL AND expires_at <= ?1 \
         AND (?2 IS NULL OR namespace = ?2) {} \
         ORDER BY created_at ASC, id ASC LIMIT ?3 OFFSET ?4",
        crate::models::lifecycle_visible_clause("")
    );
    let mut stmt = conn.prepare(&sql).context("prepare expired-unswept page")?;
    let rows = stmt
        .query_map(
            params![now, namespace, limit, offset],
            crate::storage::row_to_memory,
        )
        .context("query expired-unswept page")?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .context("map expired-unswept row")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROW_ID: &str = "a-1";

    fn base_row() -> Value {
        serde_json::json!({
            "id": ROW_ID, "tier": "long", "namespace": "ns", "title": "t",
            "content": "c", "priority": 5, "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z", "archived_at": "2026-02-01T00:00:00Z",
            "archive_reason": "r", "tags": ["x"], "metadata": {"agent_id": "a"},
        })
    }

    #[test]
    fn issue_8888_archived_row_decode_refuses_each_missing_required_key() {
        for key in REQUIRED_ARCHIVED_KEYS {
            let mut row = base_row();
            row.as_object_mut().map(|o| o.remove(*key));
            let err = ArchivedRowFields::from_json(&row).expect_err("missing key refused");
            let text = err.to_string();
            assert!(
                text.contains(&format!("`{key}`")),
                "refusal names the key {key}: {text}"
            );
        }
    }

    #[test]
    fn issue_8888_archived_row_decode_keeps_json_columns_as_text() {
        let f = ArchivedRowFields::from_json(&base_row()).expect("decode");
        assert_eq!(f.tags_json, r#"["x"]"#);
        assert_eq!(f.metadata_json, r#"{"agent_id":"a"}"#);
        assert_eq!(f.archived_at, "2026-02-01T00:00:00Z");
    }
}
