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

/// #4287 — bound on the re-read / re-apply cycle when a concurrent writer
/// keeps moving the row's version. Same shape as the auto-tag worker's
/// version-conflict retry (`background/auto_tag_worker.rs`); past the bound
/// the write is refused and reported, never forced over the newer row.
const MAX_PERSIST_ATTEMPTS: usize = 3;

/// #4287 — version-checked metadata write-back for the curator sweep.
///
/// The sweep holds a snapshot of each memory taken before its LLM call. The
/// pre-fix helpers cloned that snapshot's whole `metadata`, added one key and
/// wrote it back through the version-less `db::update`, so a metadata edit
/// committed while the model ran (another agent, the HTTP/MCP API, the CLI)
/// was silently replaced. Now the write is pinned to the version the
/// metadata was read at (`update_with_expected_version`); on a
/// `VersionConflict` the row is re-read and ONLY the curator's own key is
/// re-applied to the fresh metadata, up to [`MAX_PERSIST_ATTEMPTS`] times.
fn persist_metadata_key(
    conn: &Connection,
    mem: &Memory,
    what: &str,
    apply: impl Fn(&mut serde_json::Map<String, serde_json::Value>),
) -> Result<()> {
    let mut metadata = mem.metadata.clone();
    let mut version = mem.version;
    for _ in 0..MAX_PERSIST_ATTEMPTS {
        let mut updated = metadata.clone();
        apply(metadata_object_mut(&mut updated, &mem.id, what)?);
        match db::update_with_expected_version(
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
            None,
            Some(version),
            None,
        ) {
            Ok(_) => return Ok(()),
            Err(e) if e.downcast_ref::<db::VersionConflict>().is_some() => {
                let fresh = db::get(conn, &mem.id)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "refusing to write {what} for memory {}: the row vanished while the \
                         curator was writing it",
                        mem.id
                    )
                })?;
                metadata = fresh.metadata;
                version = fresh.version;
            }
            Err(e) => return Err(e),
        }
    }
    anyhow::bail!(
        "refusing to write {what} for memory {}: its metadata changed under the curator \
         {MAX_PERSIST_ATTEMPTS} times in a row; skipped this cycle so the newer edit is kept",
        mem.id
    )
}

pub(super) fn persist_auto_tags(conn: &Connection, mem: &Memory, tags: &[String]) -> Result<()> {
    persist_metadata_key(conn, mem, "auto_tags", |obj| {
        obj.insert("auto_tags".to_string(), serde_json::json!(tags));
        obj.insert(
            "curated_at".to_string(),
            serde_json::json!(chrono::Utc::now().to_rfc3339()),
        );
    })
}

pub(super) fn persist_contradiction(
    conn: &Connection,
    mem: &Memory,
    against_id: &str,
) -> Result<()> {
    persist_metadata_key(conn, mem, field_names::CONFIRMED_CONTRADICTIONS, |obj| {
        let mut ids: Vec<String> = obj
            .get(field_names::CONFIRMED_CONTRADICTIONS)
            .and_then(|v| v.as_array())
            .map(|existing| {
                existing
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if !ids.iter().any(|id| id == against_id) {
            ids.push(against_id.to_string());
        }
        obj.insert(
            field_names::CONFIRMED_CONTRADICTIONS.to_string(),
            serde_json::json!(ids),
        );
    })
}
