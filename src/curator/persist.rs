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

/// #9300 — the refusal reason when a row a curator verdict was computed from
/// changed after the sweep read it.
pub(super) const REASON_STALE_SNAPSHOT: &str =
    "the row changed after the sweep read it (stale snapshot); nothing written";

/// #9300 — typed refusal: the verdict (auto tags, a contradiction) was
/// computed from a sweep snapshot whose title or content no longer matches
/// the stored row, so writing it would record a verdict about content the row
/// no longer holds. Nothing is written and the row is never counted as done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StaleSnapshotRefused {
    what: String,
    mem_id: String,
}

impl std::fmt::Display for StaleSnapshotRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refusing to write {} for memory {}: {REASON_STALE_SNAPSHOT}",
            self.what, self.mem_id
        )
    }
}

impl std::error::Error for StaleSnapshotRefused {}

/// #4287 — the row a curator write-back starts from: the CURRENT row, read
/// inside the caller's write transaction. The sweep's `mem` snapshot can be
/// minutes old (an LLM call sits between the read and the write), so merging
/// into `mem.metadata` and writing the whole object back replaced every key
/// another writer had committed since — a lost update. A row that vanished
/// meanwhile is refused, never reported as written.
fn current_row(conn: &Connection, mem_id: &str, what: &str) -> Result<Memory> {
    db::get(conn, mem_id)?.ok_or_else(|| {
        anyhow::anyhow!("refusing to write {what} for memory {mem_id}: the row no longer exists")
    })
}

/// #9300 — refuse when a field the verdict was computed from differs between
/// the sweep snapshot and the current row. Metadata is NOT compared: a
/// concurrent metadata-only write does not change what the verdict is about,
/// and #4287 merges it instead of refusing it.
fn refuse_if_stale(stale: bool, mem_id: &str, what: &str) -> Result<()> {
    if stale {
        return Err(StaleSnapshotRefused {
            what: what.to_string(),
            mem_id: mem_id.to_string(),
        }
        .into());
    }
    Ok(())
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
        let current = current_row(conn, &mem.id, "auto_tags")?;
        // #9300 — the tags were computed from the snapshot's title + content.
        refuse_if_stale(
            current.title != mem.title || current.content != mem.content,
            &mem.id,
            "auto_tags",
        )?;
        let mut updated = current.metadata;
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

/// `against` is the sweep's snapshot of the contradicting row: the verdict was
/// computed from BOTH rows' content, so both are re-checked inside the write
/// transaction (#9300).
pub(super) fn persist_contradiction(
    conn: &Connection,
    mem: &Memory,
    against: &Memory,
) -> Result<()> {
    let what = field_names::CONFIRMED_CONTRADICTIONS;
    let against_id = against.id.as_str();
    db::in_write_txn(conn, || {
        let current = current_row(conn, &mem.id, what)?;
        refuse_if_stale(current.content != mem.content, &mem.id, what)?;
        let current_against = current_row(conn, against_id, what)?;
        refuse_if_stale(current_against.content != against.content, against_id, what)?;
        let mut updated = current.metadata;
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
        seeded_as(conn, "anchor-4287")
    }

    fn seeded_as(conn: &Connection, title: &str) -> Memory {
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: crate::models::Tier::Long,
            namespace: "curate-4287".to_string(),
            title: title.to_string(),
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
        let (one, two) = (seeded_as(&conn, "sibling-1"), seeded_as(&conn, "sibling-2"));
        // Both calls carry the SAME stale snapshot, as two sweep passes do.
        persist_contradiction(&conn, &stale, &one).expect("first");
        persist_contradiction(&conn, &stale, &two).expect("second");
        persist_contradiction(&conn, &stale, &one).expect("dup");
        let meta = metadata(&conn, &stale.id);
        assert_eq!(meta["note"], serde_json::json!("v1"), "lost update: {meta}");
        assert_eq!(
            meta[field_names::CONFIRMED_CONTRADICTIONS],
            serde_json::json!([one.id, two.id]),
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
        let sibling = seeded_as(&conn, "sibling-vanished-case");
        let err = persist_contradiction(&conn, &stale, &sibling).expect_err("vanished row");
        assert_eq!(
            err.to_string(),
            format!(
                "refusing to write {} for memory {}: the row no longer exists",
                field_names::CONFIRMED_CONTRADICTIONS,
                stale.id
            )
        );
    }

    /// #9300 — another writer edits the row's content or title after the
    /// sweep read it: the verdict is about content the row no longer holds.
    fn concurrent_edit(conn: &Connection, id: &str, title: Option<&str>, content: Option<&str>) {
        db::update(
            conn, id, title, content, None, None, None, None, None, None, None,
        )
        .expect("concurrent edit");
    }

    const EDITED_TITLE_9300: &str = "edited-title-9300";
    const EDITED_CONTENT_9300: &str = "edited content after the sweep read the row (#9300)";

    /// The two inputs of an auto-tag verdict: (case, title edit, content edit).
    const AUTO_TAG_STALE_CASES_9300: [(&str, Option<&str>, Option<&str>); 2] = [
        ("content edited", None, Some(EDITED_CONTENT_9300)),
        ("title edited", Some(EDITED_TITLE_9300), None),
    ];

    #[test]
    fn persist_9300_auto_tags_refuses_a_stale_snapshot_and_writes_nothing() {
        for (case, title, content) in AUTO_TAG_STALE_CASES_9300 {
            let dir = tempfile::tempdir().expect("tempdir");
            let conn = db::open(&dir.path().join("c.db")).expect("open");
            let stale = seeded(&conn);
            concurrent_edit(&conn, &stale.id, title, content);
            let before = db::get(&conn, &stale.id).expect("get").expect("row");
            let err = persist_auto_tags(&conn, &stale, &["alpha".to_string()])
                .expect_err("a stale snapshot must be refused");
            assert_eq!(
                err.to_string(),
                format!(
                    "refusing to write auto_tags for memory {}: {REASON_STALE_SNAPSHOT}",
                    stale.id
                ),
                "{case}"
            );
            assert!(
                err.downcast_ref::<StaleSnapshotRefused>().is_some(),
                "{case}: typed"
            );
            let after = db::get(&conn, &stale.id).expect("get").expect("row");
            assert_eq!(after.metadata, before.metadata, "{case}: nothing written");
            assert_eq!(after.version, before.version, "{case}: no write landed");
            assert_eq!(
                (after.title.as_str(), after.content.as_str()),
                (before.title.as_str(), before.content.as_str()),
                "{case}: the concurrent edit survives"
            );
        }
    }

    #[test]
    fn persist_9300_contradiction_refuses_when_either_row_changed() {
        // (case, edit the anchor row?) — the verdict reads BOTH rows' content.
        for (case, edit_anchor) in [("anchor edited", true), ("contradicting row edited", false)] {
            let dir = tempfile::tempdir().expect("tempdir");
            let conn = db::open(&dir.path().join("c.db")).expect("open");
            let stale = seeded(&conn);
            let against = seeded_as(&conn, "contradicting-9300");
            let edited = if edit_anchor { &stale.id } else { &against.id };
            concurrent_edit(&conn, edited, None, Some(EDITED_CONTENT_9300));
            let before = db::get(&conn, &stale.id).expect("get").expect("row");
            let err = persist_contradiction(&conn, &stale, &against)
                .expect_err("a stale snapshot must be refused");
            assert_eq!(
                err.to_string(),
                format!(
                    "refusing to write {} for memory {edited}: {REASON_STALE_SNAPSHOT}",
                    field_names::CONFIRMED_CONTRADICTIONS
                ),
                "{case}"
            );
            assert!(
                err.downcast_ref::<StaleSnapshotRefused>().is_some(),
                "{case}: typed"
            );
            let after = db::get(&conn, &stale.id).expect("get").expect("row");
            assert_eq!(after.metadata, before.metadata, "{case}: nothing written");
            assert_eq!(after.version, before.version, "{case}: no write landed");
        }
    }
}
