// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #1720 B3 — boot-time owner-lockout probe.
//!
//! A read-only COUNT over the indexed visibility generated columns that
//! tells the boot guard ([`crate::identity::enforce_owner_lockout_guard`])
//! how many pre-existing `scope=private` rows would become invisible to a
//! freshly-configured `AI_MEMORY_AGENT_ID` caller. Split out of the
//! oversized `storage/mod.rs` per the qual_10 module-size ceiling.

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};

/// Counts `scope=private` rows that would become INVISIBLE to `caller`
/// once read-path ownership filtering is enabled, and returns one sample
/// owner id of such a row (or `None` when the hidden rows are all
/// unowned).
///
/// Mirrors the A2 private visibility predicate exactly: a private row is
/// visible to `caller` iff `agent_id_idx = caller` OR
/// `target_agent_id_idx = caller` (the inbox carve-out). So a private row
/// is HIDDEN from `caller` iff neither matches — including rows with a
/// NULL owner (`agent_id_idx IS NULL`), which the `COALESCE(.., '')`
/// renders as a non-match. Reads the indexed generated columns
/// (`scope_idx` defaults to `'private'`; `agent_id_idx` /
/// `target_agent_id_idx` project `metadata`), so it is a single indexed
/// COUNT — no full scan, no per-row JSON parse.
///
/// A non-zero count means the operator set `AI_MEMORY_AGENT_ID` to an id
/// that does NOT own their pre-existing private rows, so enabling
/// enforcement would lock them out of their own memories until
/// `ai-memory reown` re-owns them.
///
/// # Errors
///
/// Returns the underlying SQLite error.
pub fn count_private_rows_hidden_from(
    conn: &Connection,
    caller: &str,
) -> Result<(i64, Option<String>)> {
    const HIDDEN_PREDICATE: &str = "scope_idx = 'private' \
         AND COALESCE(agent_id_idx, '') <> ?1 \
         AND COALESCE(target_agent_id_idx, '') <> ?1";
    let hidden: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM memories WHERE {HIDDEN_PREDICATE}"),
        params![caller],
        |r| r.get(0),
    )?;
    if hidden == 0 {
        return Ok((0, None));
    }
    // One representative owner of a hidden row (skip the unowned ones so
    // the operator sees a concrete legacy id like `host:laptop:pid-123`).
    let sample: Option<String> = conn
        .query_row(
            &format!(
                "SELECT agent_id_idx FROM memories \
                 WHERE {HIDDEN_PREDICATE} AND agent_id_idx IS NOT NULL LIMIT 1"
            ),
            params![caller],
            |r| r.get(0),
        )
        .optional()?;
    Ok((hidden, sample))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fresh in-memory DB (migrations applied by `storage::open`) seeded
    /// via raw INSERTs. The VIRTUAL generated columns project the metadata
    /// at query time, so a row carrying a metadata JSON is sufficient.
    fn db() -> Connection {
        crate::storage::open(std::path::Path::new(":memory:")).unwrap()
    }

    fn insert(conn: &Connection, id: &str, meta: &serde_json::Value) {
        conn.execute(
            "INSERT INTO memories \
                 (id, tier, namespace, title, content, created_at, updated_at, metadata) \
             VALUES (?1,'long','ns',?1,'c','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',?2)",
            params![id, meta.to_string()],
        )
        .unwrap();
    }

    /// Counts private rows the caller does NOT own; ignores public/
    /// collective rows + the caller's own rows; counts the inbox carve-out
    /// (`target_agent_id == caller`) as VISIBLE. The sample owner is a
    /// concrete other-owner id, skipping unowned rows.
    #[test]
    fn counts_only_hidden_private_rows() {
        let conn = db();
        // Owned by another id, private — HIDDEN from bob.
        insert(
            &conn,
            "a-priv",
            &serde_json::json!({"agent_id": "host:laptop:pid-9", "scope": "private"}),
        );
        // Owned by bob, private — VISIBLE (his own).
        insert(
            &conn,
            "b-priv",
            &serde_json::json!({"agent_id": "bob", "scope": "private"}),
        );
        // Collective scope — VISIBLE to everyone.
        insert(
            &conn,
            "a-pub",
            &serde_json::json!({"agent_id": "alice", "scope": "collective"}),
        );
        // Private, no owner — HIDDEN (un-ownable under the predicate).
        insert(&conn, "unowned", &serde_json::json!({"scope": "private"}));
        // Private, addressed to bob's inbox — VISIBLE via target carve-out.
        insert(
            &conn,
            "inbox",
            &serde_json::json!({"agent_id": "carol", "target_agent_id": "bob", "scope": "private"}),
        );

        let (hidden, sample) = count_private_rows_hidden_from(&conn, "bob").unwrap();
        assert_eq!(hidden, 2, "expected exactly the 2 hidden private rows");
        assert_eq!(sample.as_deref(), Some("host:laptop:pid-9"));
    }

    /// A caller that owns every private row sees a zero count + no sample —
    /// the no-lockout (post-reown) state.
    #[test]
    fn zero_when_caller_owns_all() {
        let conn = db();
        insert(
            &conn,
            "p1",
            &serde_json::json!({"agent_id": "bob", "scope": "private"}),
        );
        // scope key absent ⇒ defaults to private via scope_idx.
        insert(&conn, "p2", &serde_json::json!({"agent_id": "bob"}));
        let (hidden, sample) = count_private_rows_hidden_from(&conn, "bob").unwrap();
        assert_eq!(hidden, 0);
        assert!(sample.is_none());
    }

    /// When all hidden private rows are unowned, the count is non-zero but
    /// the sample is `None` (nothing concrete to name).
    #[test]
    fn sample_none_when_all_hidden_unowned() {
        let conn = db();
        insert(&conn, "u1", &serde_json::json!({"scope": "private"}));
        insert(&conn, "u2", &serde_json::json!({}));
        let (hidden, sample) = count_private_rows_hidden_from(&conn, "bob").unwrap();
        assert_eq!(hidden, 2);
        assert!(sample.is_none());
    }
}
