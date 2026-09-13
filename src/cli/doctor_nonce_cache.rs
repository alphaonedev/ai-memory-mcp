// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! `ai-memory doctor` — the federation nonce-cache mirror section (issue
//! [#3662](https://github.com/alphaonedev/ai-memory-mcp/issues/3662), audit
//! #3645 F16).
//!
//! `doctor` runs in its own process, so it cannot read the live daemon's
//! in-memory counters (those are on `/health` under `federation.nonce_cache`
//! and on `/metrics` as `ai_memory_federation_nonce_cache_*`). What it CAN
//! measure offline is the durable half of the contract: the sqlite mirror
//! (`federation_nonce_cache`, schema v51 / #1255) that restart protection
//! depends on. This section reports that mirror's occupancy against the
//! in-memory bounds and the age of its newest row, and says explicitly which
//! signals it cannot observe rather than printing a zero for them.
//!
//! | Check | Severity when it fails |
//! |---|---|
//! | mirror table present | **N/A** (pre-v51 schema — nothing to measure) |
//! | mirror table readable | **Critical** (a present table that cannot be read is the restart-protection store failing) |
//! | no peer holds more rows than the per-peer cap; peer count within the peer cap | **Warning** (delete-on-evict is not keeping the mirror bounded, #1690) |
//! | everything else | **Info** |
//!
//! An EMPTY mirror is Info, not a finding: a node that has never received a
//! nonce-bound federated request has nothing to persist.

use rusqlite::{Connection, OptionalExtension};

use super::doctor::{ReportSection, Severity};
use crate::identity::replay::{FEDERATION_NONCE_CAPACITY_PER_PEER, FEDERATION_NONCE_MAX_PEERS};

/// Section name. One definition, referenced by the renderer and the tests.
pub const SECTION_NONCE_CACHE: &str = "Federation nonce cache (#3662)";

/// The mirror table (schema v51 / #1255).
const TABLE: &str = "federation_nonce_cache";

/// Fact keys — one definition each so the tests and the docs cannot drift.
pub const FACT_TABLE_PRESENT: &str = "mirror_table_present";
pub const FACT_ROWS: &str = "mirror_rows";
pub const FACT_PEERS: &str = "mirror_peers";
pub const FACT_MAX_PEERS: &str = "max_peers";
pub const FACT_PER_PEER_CAPACITY: &str = "per_peer_capacity";
pub const FACT_LARGEST_PEER_ROWS: &str = "largest_peer_rows";
pub const FACT_OVER_CAPACITY_PEERS: &str = "over_capacity_peers";
pub const FACT_NEWEST_ROW: &str = "newest_row_inserted_at";
pub const FACT_LIVE_COUNTERS: &str = "live_counters";

/// What an offline `doctor` cannot see, spelled out instead of zeroed.
const LIVE_COUNTERS_NOTE: &str = "not observable offline; read /health federation.nonce_cache \
                                  or /metrics ai_memory_federation_nonce_cache_* on the daemon";

/// The mirror's measured shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorShape {
    /// Rows in the table.
    pub rows: u64,
    /// Distinct `peer_id` values.
    pub peers: u64,
    /// Rows held by the single largest peer.
    pub largest_peer_rows: u64,
    /// Peers holding more rows than `FEDERATION_NONCE_CAPACITY_PER_PEER`.
    pub over_capacity_peers: u64,
    /// `inserted_at` of the newest row (RFC3339 as stored), if any.
    pub newest_inserted_at: Option<String>,
}

/// Read the mirror. `Ok(None)` = the table is absent (pre-v51 schema).
///
/// # Errors
/// Propagates the underlying `rusqlite` error when the table exists but
/// cannot be read.
pub fn read_mirror(conn: &Connection) -> rusqlite::Result<Option<MirrorShape>> {
    let present: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [TABLE],
            |r| r.get(0),
        )
        .optional()?;
    if present.is_none() {
        return Ok(None);
    }
    #[allow(clippy::cast_possible_wrap)]
    let cap = FEDERATION_NONCE_CAPACITY_PER_PEER as i64;
    let (rows, peers, largest, over_cap): (i64, i64, i64, i64) = conn.query_row(
        "SELECT COALESCE(SUM(n), 0), COUNT(*), COALESCE(MAX(n), 0), \
                COALESCE(SUM(CASE WHEN n > ?1 THEN 1 ELSE 0 END), 0) \
         FROM (SELECT COUNT(*) AS n FROM federation_nonce_cache GROUP BY peer_id)",
        [cap],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let newest_inserted_at: Option<String> = conn
        .query_row(
            "SELECT inserted_at FROM federation_nonce_cache ORDER BY inserted_at DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    #[allow(clippy::cast_sign_loss)]
    Ok(Some(MirrorShape {
        rows: rows.max(0) as u64,
        peers: peers.max(0) as u64,
        largest_peer_rows: largest.max(0) as u64,
        over_capacity_peers: over_cap.max(0) as u64,
        newest_inserted_at,
    }))
}

/// Build the section from an open connection.
#[must_use]
pub fn section_nonce_cache_3662(conn: &Connection) -> ReportSection {
    let mut facts: Vec<(String, String)> = Vec::new();
    facts.push((
        FACT_MAX_PEERS.into(),
        FEDERATION_NONCE_MAX_PEERS.to_string(),
    ));
    facts.push((
        FACT_PER_PEER_CAPACITY.into(),
        FEDERATION_NONCE_CAPACITY_PER_PEER.to_string(),
    ));
    facts.push((FACT_LIVE_COUNTERS.into(), LIVE_COUNTERS_NOTE.into()));
    match read_mirror(conn) {
        Ok(None) => {
            facts.push((FACT_TABLE_PRESENT.into(), "no".into()));
            ReportSection {
                name: SECTION_NONCE_CACHE.into(),
                severity: Severity::NotAvailable,
                facts,
                note: Some(
                    "the federation_nonce_cache mirror table is absent (schema before v51 / \
                     #1255): nonce replay protection on this node is in-memory only and every \
                     daemon restart re-opens the replay window"
                        .into(),
                ),
            }
        }
        Err(e) => {
            facts.push((FACT_TABLE_PRESENT.into(), "unreadable".into()));
            ReportSection {
                name: SECTION_NONCE_CACHE.into(),
                severity: Severity::Critical,
                facts,
                note: Some(format!(
                    "the federation_nonce_cache mirror could not be read ({e}); the daemon's \
                     restart protection depends on this table"
                )),
            }
        }
        Ok(Some(shape)) => {
            facts.push((FACT_TABLE_PRESENT.into(), "yes".into()));
            facts.push((FACT_ROWS.into(), shape.rows.to_string()));
            facts.push((FACT_PEERS.into(), shape.peers.to_string()));
            facts.push((
                FACT_LARGEST_PEER_ROWS.into(),
                shape.largest_peer_rows.to_string(),
            ));
            facts.push((
                FACT_OVER_CAPACITY_PEERS.into(),
                shape.over_capacity_peers.to_string(),
            ));
            facts.push((
                FACT_NEWEST_ROW.into(),
                shape
                    .newest_inserted_at
                    .clone()
                    .unwrap_or_else(|| "none (mirror empty)".into()),
            ));
            let mut notes: Vec<String> = Vec::new();
            if shape.over_capacity_peers > 0 {
                notes.push(format!(
                    "{} peer(s) hold more than {} mirror rows (largest {}): the #1690 \
                     delete-on-evict prune is not keeping the disk mirror bounded — check \
                     ai_memory_federation_nonce_cache_persistence_failed_total{{op=\"delete_fingerprint\"}}",
                    shape.over_capacity_peers,
                    FEDERATION_NONCE_CAPACITY_PER_PEER,
                    shape.largest_peer_rows,
                ));
            }
            if shape.peers > FEDERATION_NONCE_MAX_PEERS as u64 {
                notes.push(format!(
                    "the mirror holds {} peers, above the in-memory ceiling of {}: evicted \
                     peer slots are not being deleted from disk — check \
                     ai_memory_federation_nonce_cache_persistence_failed_total{{op=\"delete_peer\"}}",
                    shape.peers, FEDERATION_NONCE_MAX_PEERS,
                ));
            }
            ReportSection {
                name: SECTION_NONCE_CACHE.into(),
                severity: if notes.is_empty() {
                    Severity::Info
                } else {
                    Severity::Warning
                },
                facts,
                note: if notes.is_empty() {
                    None
                } else {
                    Some(notes.join("; "))
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FACT_LARGEST_PEER_ROWS, FACT_NEWEST_ROW, FACT_OVER_CAPACITY_PEERS, FACT_PEERS, FACT_ROWS,
        FACT_TABLE_PRESENT, SECTION_NONCE_CACHE, read_mirror, section_nonce_cache_3662,
    };
    use crate::cli::doctor::Severity;
    use crate::identity::replay::FEDERATION_NONCE_CAPACITY_PER_PEER;

    fn fact<'a>(section: &'a crate::cli::doctor::ReportSection, key: &str) -> &'a str {
        section
            .facts
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("fact {key} missing in {}", section.name))
    }

    fn migrated_db() -> (tempfile::TempDir, rusqlite::Connection) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("doctor-3662.db");
        let conn = crate::db::open(&path).expect("open + migrate");
        (dir, conn)
    }

    fn seed(conn: &rusqlite::Connection, peer: &str, n: usize, inserted_at: &str) {
        conn.execute_batch("BEGIN").expect("begin seed txn");
        for i in 0..n {
            let fp = [u8::try_from(i % 251).unwrap(); 32];
            let mut fp = fp;
            fp[0] = u8::try_from(i / 251).unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO federation_nonce_cache \
                 (peer_id, fingerprint, last_touch, inserted_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![peer, fp.as_slice(), i64::try_from(i).unwrap(), inserted_at],
            )
            .expect("seed row");
        }
        conn.execute_batch("COMMIT").expect("commit seed txn");
    }

    #[test]
    fn empty_mirror_is_info_3662() {
        let (_dir, conn) = migrated_db();
        let s = section_nonce_cache_3662(&conn);
        assert_eq!(s.name, SECTION_NONCE_CACHE);
        assert_eq!(s.severity, Severity::Info);
        assert_eq!(fact(&s, FACT_TABLE_PRESENT), "yes");
        assert_eq!(fact(&s, FACT_ROWS), "0");
        assert_eq!(fact(&s, FACT_PEERS), "0");
        assert!(fact(&s, FACT_NEWEST_ROW).starts_with("none"));
        assert!(s.note.is_none());
    }

    #[test]
    fn bounded_mirror_reports_measured_shape_3662() {
        let (_dir, conn) = migrated_db();
        seed(&conn, "peer-a", 3, "2026-09-13T10:00:00+00:00");
        seed(&conn, "peer-b", 5, "2026-09-13T11:00:00+00:00");
        let s = section_nonce_cache_3662(&conn);
        assert_eq!(s.severity, Severity::Info);
        assert_eq!(fact(&s, FACT_ROWS), "8");
        assert_eq!(fact(&s, FACT_PEERS), "2");
        assert_eq!(fact(&s, FACT_LARGEST_PEER_ROWS), "5");
        assert_eq!(fact(&s, FACT_OVER_CAPACITY_PEERS), "0");
        assert_eq!(fact(&s, FACT_NEWEST_ROW), "2026-09-13T11:00:00+00:00");
    }

    #[test]
    fn over_capacity_peer_is_warning_3662() {
        let (_dir, conn) = migrated_db();
        seed(
            &conn,
            "peer-flood",
            FEDERATION_NONCE_CAPACITY_PER_PEER + 1,
            "2026-09-13T12:00:00+00:00",
        );
        let s = section_nonce_cache_3662(&conn);
        assert_eq!(s.severity, Severity::Warning);
        assert_eq!(fact(&s, FACT_OVER_CAPACITY_PEERS), "1");
        assert_eq!(
            fact(&s, FACT_LARGEST_PEER_ROWS),
            (FEDERATION_NONCE_CAPACITY_PER_PEER + 1).to_string()
        );
        assert!(
            s.note
                .as_deref()
                .is_some_and(|n| n.contains("delete_fingerprint")),
            "note must point at the persistence-failure series: {:?}",
            s.note
        );
    }

    #[test]
    fn absent_table_is_not_available_not_zero_3662() {
        let (_dir, conn) = migrated_db();
        conn.execute_batch("DROP TABLE federation_nonce_cache")
            .expect("drop");
        assert_eq!(read_mirror(&conn).expect("read"), None);
        let s = section_nonce_cache_3662(&conn);
        assert_eq!(s.severity, Severity::NotAvailable);
        assert_eq!(fact(&s, FACT_TABLE_PRESENT), "no");
        assert!(
            !s.facts.iter().any(|(k, _)| k == FACT_ROWS),
            "an absent mirror must not report a row count of 0"
        );
    }

    #[test]
    fn unreadable_table_is_critical_3662() {
        let (_dir, conn) = migrated_db();
        // A table with the right name but not the mirror's columns: present,
        // but the shape query fails.
        conn.execute_batch(
            "DROP TABLE federation_nonce_cache; CREATE TABLE federation_nonce_cache (x INTEGER)",
        )
        .expect("replace");
        let s = section_nonce_cache_3662(&conn);
        assert_eq!(s.severity, Severity::Critical);
        assert_eq!(fact(&s, FACT_TABLE_PRESENT), "unreadable");
    }
}
