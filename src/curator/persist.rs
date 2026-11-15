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

/// #4287 — the metadata a curator write-back starts from: the row's CURRENT
/// metadata, read inside the caller's write transaction. The sweep's `mem`
/// snapshot can be minutes old (an LLM call sits between the read and the
/// write), so merging into `mem.metadata` and writing the whole object back
/// replaced every key another writer had committed since — a lost update.
/// A row that vanished meanwhile is refused, never reported as written.
fn current_metadata(conn: &Connection, mem_id: &str, what: &str) -> Result<serde_json::Value> {
    db::get(conn, mem_id)?.map(|m| m.metadata).ok_or_else(|| {
        anyhow::anyhow!("refusing to write {what} for memory {mem_id}: the row no longer exists")
    })
}

/// #4287 — write `metadata` back as the row's whole metadata object. Runs
/// inside the caller's [`db::in_write_txn`], so nothing lands between the
/// read in [`current_metadata`] and this UPDATE.
fn write_metadata(conn: &Connection, mem_id: &str, metadata: &serde_json::Value) -> Result<()> {
    db::update(
        conn,
        mem_id,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(metadata),
    )?;
    Ok(())
}

pub(super) fn persist_auto_tags(conn: &Connection, mem: &Memory, tags: &[String]) -> Result<()> {
    db::in_write_txn(conn, || {
        let mut updated = current_metadata(conn, &mem.id, "auto_tags")?;
        {
            let obj = metadata_object_mut(&mut updated, &mem.id, "auto_tags")?;
            obj.insert("auto_tags".to_string(), serde_json::json!(tags));
            obj.insert(
                "curated_at".to_string(),
                serde_json::json!(chrono::Utc::now().to_rfc3339()),
            );
        }
        write_metadata(conn, &mem.id, &updated)
    })
}

pub(super) fn persist_contradiction(
    conn: &Connection,
    mem: &Memory,
    against_id: &str,
) -> Result<()> {
    let what = field_names::CONFIRMED_CONTRADICTIONS;
    db::in_write_txn(conn, || {
        let mut updated = current_metadata(conn, &mem.id, what)?;
        {
            let obj = metadata_object_mut(&mut updated, &mem.id, what)?;
            let existing = obj
                .get(what)
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
            obj.insert(what.to_string(), serde_json::json!(ids));
        }
        write_metadata(conn, &mem.id, &updated)
    })
}

#[cfg(test)]
mod lost_update_4287_tests {
    use super::*;

    fn seeded(conn: &Connection) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Long,
            namespace: "curate-4287".to_string(),
            title: "anchor-4287".to_string(),
            content: "a".repeat(120),
            priority: 5,
            confidence: 1.0,
            source: "api".to_string(),
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({"note": "v0"}),
            version: 1,
            ..Memory::default()
        };
        db::insert(conn, &mem).expect("seed");
        mem
    }

    /// Another writer commits `note = v1` after the sweep read the row.
    fn concurrent_note_write(conn: &Connection, id: &str) {
        let mut meta = db::get(conn, id).expect("get").expect("row").metadata;
        meta["note"] = serde_json::json!("v1");
        db::update(
            conn,
            id,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&meta),
        )
        .expect("concurrent write");
    }

    fn metadata(conn: &Connection, id: &str) -> serde_json::Value {
        db::get(conn, id).expect("get").expect("row").metadata
    }

    #[test]
    fn persist_4287_auto_tags_keeps_a_concurrent_metadata_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = db::open(&dir.path().join("c.db")).expect("open");
        let stale = seeded(&conn);
        concurrent_note_write(&conn, &stale.id);
        persist_auto_tags(&conn, &stale, &["alpha".to_string()]).expect("persist");
        let meta = metadata(&conn, &stale.id);
        assert_eq!(meta["note"], serde_json::json!("v1"), "lost update: {meta}");
        assert_eq!(meta["auto_tags"], serde_json::json!(["alpha"]), "{meta}");
    }

    #[test]
    fn persist_4287_contradiction_keeps_every_id_from_stale_snapshots() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = db::open(&dir.path().join("c.db")).expect("open");
        let stale = seeded(&conn);
        concurrent_note_write(&conn, &stale.id);
        // Both calls carry the SAME stale snapshot, as two sweep passes do.
        persist_contradiction(&conn, &stale, "id-1").expect("first");
        persist_contradiction(&conn, &stale, "id-2").expect("second");
        persist_contradiction(&conn, &stale, "id-1").expect("dup");
        let meta = metadata(&conn, &stale.id);
        assert_eq!(meta["note"], serde_json::json!("v1"), "lost update: {meta}");
        assert_eq!(
            meta[field_names::CONFIRMED_CONTRADICTIONS],
            serde_json::json!(["id-1", "id-2"]),
            "{meta}"
        );
    }

    #[test]
    fn persist_4287_vanished_row_is_refused_not_reported_written() {
        let dir = tempfile::tempdir().expect("tempdir");
        let conn = db::open(&dir.path().join("c.db")).expect("open");
        let stale = seeded(&conn);
        assert!(db::delete(&conn, &stale.id).expect("delete"));
        let err = persist_auto_tags(&conn, &stale, &[]).expect_err("vanished row");
        assert_eq!(
            err.to_string(),
            format!(
                "refusing to write auto_tags for memory {}: the row no longer exists",
                stale.id
            )
        );
        let err = persist_contradiction(&conn, &stale, "x").expect_err("vanished row");
        assert_eq!(
            err.to_string(),
            format!(
                "refusing to write {} for memory {}: the row no longer exists",
                field_names::CONFIRMED_CONTRADICTIONS,
                stale.id
            )
        );
    }
}
