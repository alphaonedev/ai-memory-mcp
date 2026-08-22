// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Write-back helpers for the curator sweep.
//!
//! Extracted from the original flat `src/curator.rs` in v0.7.0 Layer
//! 0.5 Task L0.5-1. Pure refactor — no semantic changes. These
//! functions are the only path inside the curator that mutates the
//! database; `run_once` guards every call with a `dry_run` check.

use crate::models::field_names;
use anyhow::Result;
use rusqlite::Connection;

use crate::db;
use crate::models::Memory;

/// ERRORS-19 / fail-closed — borrow a memory's metadata as a JSON object,
/// or return a descriptive error naming the row and what was refused.
///
/// `Memory::metadata` is a bare `serde_json::Value`, so a row whose stored
/// `metadata` column holds any non-object JSON (`null`, an array, a bare
/// string) yields `None` from `as_object_mut`. The pre-fix helpers below
/// treated that as a no-op, wrote the metadata back UNCHANGED, returned
/// `Ok(())`, and let `run_once` increment `auto_tagged` /
/// `contradictions_found` — a lost write self-reported as a success. A
/// curator that claims work it did not do is worse than one that refuses:
/// the caller now records the failure in `report.errors` and the counter
/// stays honest.
fn metadata_object_mut<'a>(
    value: &'a mut serde_json::Value,
    mem_id: &str,
    what: &str,
) -> Result<&'a mut serde_json::Map<String, serde_json::Value>> {
    let kind = match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    };
    value.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!(
            "refusing to write {what} for memory {mem_id}: metadata is a JSON {kind}, not an \
             object — the update would silently discard the write"
        )
    })
}

pub(super) fn persist_auto_tags(conn: &Connection, mem: &Memory, tags: &[String]) -> Result<()> {
    let mut updated = mem.metadata.clone();
    {
        let obj = metadata_object_mut(&mut updated, &mem.id, "auto_tags")?;
        obj.insert("auto_tags".to_string(), serde_json::json!(tags));
        obj.insert(
            "curated_at".to_string(),
            serde_json::json!(chrono::Utc::now().to_rfc3339()),
        );
    }
    db::update(
        conn,
        &mem.id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&updated),
    )?;
    Ok(())
}

pub(super) fn persist_contradiction(
    conn: &Connection,
    mem: &Memory,
    against_id: &str,
) -> Result<()> {
    let mut updated = mem.metadata.clone();
    {
        let obj =
            metadata_object_mut(&mut updated, &mem.id, field_names::CONFIRMED_CONTRADICTIONS)?;
        let existing = obj
            .get(field_names::CONFIRMED_CONTRADICTIONS)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut ids: Vec<String> = existing
            .into_iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        if !ids.iter().any(|id| id == against_id) {
            ids.push(against_id.to_string());
        }
        obj.insert(
            field_names::CONFIRMED_CONTRADICTIONS.to_string(),
            serde_json::json!(ids),
        );
    }
    db::update(
        conn,
        &mem.id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&updated),
    )?;
    Ok(())
}
