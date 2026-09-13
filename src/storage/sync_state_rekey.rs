// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3675 — heal a `sync_state` row keyed by a RAW peer URL.
//!
//! Before #3675 `sync-daemon` keyed `sync_state.peer_id` by the verbatim
//! `--peers` URL, so a `user:pass@` userinfo or a `?token=` query string
//! was persisted in plaintext and survived into every backup and `VACUUM
//! INTO` snapshot. The key is now the allowlist rendering
//! (`url_display::url_origin_and_path`). This module moves a pre-existing
//! row from the raw key to the rendered key — cursors folded through the
//! refuse-to-regress upserts, never overwritten backwards — and deletes
//! the raw row, so the at-rest copy is gone on the first cycle after the
//! upgrade and the peer keeps its pull / push watermarks (no re-pull of
//! the whole window).

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension as _, params};

/// Fold the `sync_state` row keyed `raw_key` (if any) into the row keyed
/// `rendered_key`, then delete the raw row. A no-op when the two keys are
/// equal (an uncredentialed URL renders to itself) or when no raw row
/// exists.
///
/// Returns `true` when a row was moved.
///
/// # Errors
/// Any sqlite error from the fold or the delete; the two run in one
/// transaction so a failure leaves both rows as they were.
pub fn rekey_peer(
    conn: &Connection,
    agent_id: &str,
    raw_key: &str,
    rendered_key: &str,
) -> Result<bool> {
    if raw_key == rendered_key {
        return Ok(false);
    }
    let tx = conn.unchecked_transaction()?;
    let row: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT last_seen_at, last_pushed_at FROM sync_state \
             WHERE agent_id = ?1 AND peer_id = ?2",
            params![agent_id, raw_key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((last_seen_at, last_pushed_at)) = row else {
        return Ok(false);
    };
    super::sync_state_observe(&tx, agent_id, rendered_key, &last_seen_at)?;
    if let Some(pushed) = last_pushed_at.as_deref() {
        super::sync_state_record_push(&tx, agent_id, rendered_key, pushed)?;
    }
    tx.execute(
        "DELETE FROM sync_state WHERE agent_id = ?1 AND peer_id = ?2",
        params![agent_id, raw_key],
    )?;
    tx.commit()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = "https://alice:s3cr3t@peer.example:9077/mesh?token=qpw";
    const RENDERED: &str = "https://peer.example:9077/mesh";

    fn open() -> Connection {
        crate::storage::open(std::path::Path::new(":memory:")).expect("in-memory db")
    }

    #[test]
    fn raw_keyed_row_moves_to_the_rendered_key_and_is_deleted_3675() {
        let conn = open();
        super::super::sync_state_observe(&conn, "me", RAW, "2026-09-01T00:00:00Z").unwrap();
        super::super::sync_state_record_push(&conn, "me", RAW, "2026-09-02T00:00:00Z").unwrap();
        assert!(rekey_peer(&conn, "me", RAW, RENDERED).unwrap());
        let clock = super::super::sync_state_load(&conn, "me").unwrap();
        assert_eq!(
            clock.entries.get(RENDERED).map(String::as_str),
            Some("2026-09-01T00:00:00Z")
        );
        assert!(clock.entries.get(RAW).is_none(), "raw row must be gone");
        assert_eq!(
            super::super::sync_state_last_pushed(&conn, "me", RENDERED).as_deref(),
            Some("2026-09-02T00:00:00Z")
        );
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_state WHERE peer_id LIKE '%s3cr3t%' OR peer_id LIKE '%qpw%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0, "no credential survives at rest");
        // Idempotent: nothing left to move.
        assert!(!rekey_peer(&conn, "me", RAW, RENDERED).unwrap());
    }

    #[test]
    fn rekey_never_regresses_an_existing_rendered_cursor_3675() {
        let conn = open();
        super::super::sync_state_observe(&conn, "me", RENDERED, "2026-09-05T00:00:00Z").unwrap();
        super::super::sync_state_observe(&conn, "me", RAW, "2026-09-01T00:00:00Z").unwrap();
        assert!(rekey_peer(&conn, "me", RAW, RENDERED).unwrap());
        let clock = super::super::sync_state_load(&conn, "me").unwrap();
        assert_eq!(
            clock.entries.get(RENDERED).map(String::as_str),
            Some("2026-09-05T00:00:00Z")
        );
    }

    #[test]
    fn equal_keys_are_a_no_op_3675() {
        let conn = open();
        assert!(!rekey_peer(&conn, "me", RENDERED, RENDERED).unwrap());
    }
}
