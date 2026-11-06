// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7228 (items 1 and 3) - the audit-watermark WRITERS must never emit a
//! db_id-less (legacy, pre-#2955) `audit_watermark` row into the shared
//! on-host forensic sink.
//!
//! The defect: both append chokepoints (the sqlite signed-events writer and the
//! postgres in-tx writer) resolved the genesis-derived `db_id`, and on `None`
//! (no genesis row yet) or on a genesis read error (`.ok()`) still emitted the
//! watermark WITHOUT a `db_id`. The reader counts every db_id-less row for
//! EVERY opener, so one genesis-less store anchored a foreign high-water that
//! convicted every other database on the host of truncation.
//!
//! Pins, on both backends:
//! - a store with NO genesis row emits NO watermark row at the interval;
//! - a store WITH a genesis row still emits IDENTIFIED rows (no over-suppression).
//!
//! The throttle (`LAST_WATERMARKED_SEQ`) is process-global and cannot be reset,
//! so every cell drives its chain past `HIGH_WATER + 2 * WATERMARK_INTERVAL`
//! and the cells serialise through one lock.

#![allow(clippy::missing_panics_doc)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};

use ai_memory::governance::audit as forensic;
use ai_memory::signed_events::{SignedEvent, append_signed_event, genesis_db_id, payload_hash};
use rusqlite::Connection;

/// Serialises every cell (the forensic sink and the throttle are process-global).
static CELL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Highest chain head any cell has driven: an upper bound for the process-wide
/// throttle's last-anchored sequence.
static HIGH_WATER: AtomicI64 = AtomicI64::new(0);

/// Rows appended before the genesis row is removed (genesis + one successor).
const ROWS_BEFORE_GENESIS_REMOVAL: i64 = 2;

/// Sequence of the genesis row.
const GENESIS_SEQUENCE: i64 = 1;

/// Forensic `kind` of the watermark row.
const WATERMARK_KIND: &str = "audit_watermark";

/// Chain head every cell must reach: past the throttle by two intervals.
fn target_head() -> i64 {
    HIGH_WATER.load(Ordering::SeqCst) + 2 * forensic::WATERMARK_INTERVAL
}

/// Tempdirs under `.local-runs/` (project no-`/tmp` HARD RULE).
fn fresh_dir(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-7228-watermark-requires-genesis");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// Every `audit_watermark` payload in the sink at `dir`.
fn watermark_payloads(dir: &Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read sink dir").flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(forensic::FORENSIC_FILE_PREFIX) {
            continue;
        }
        let text = std::fs::read_to_string(entry.path()).expect("read forensic file");
        for line in text.lines() {
            let Ok(row) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if row.get("kind").and_then(serde_json::Value::as_str) == Some(WATERMARK_KIND)
                && let Some(payload) = row.get("payload")
            {
                out.push(payload.clone());
            }
        }
    }
    out
}

fn open_db(dir: &Path) -> Connection {
    let path = dir.join("audit.db");
    drop(ai_memory::db::open(&path).expect("init db"));
    ai_memory::db::open(&path).expect("open db")
}

fn append_row(conn: &Connection, n: i64) {
    let ev = SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: "alice".to_string(),
        event_type: "memory_link.created".to_string(),
        payload_hash: payload_hash(format!("row-{n}").as_bytes()),
        signature: None,
        attest_level: "unsigned".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    };
    append_signed_event(conn, &ev).expect("append");
}

fn head(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM signed_events",
        [],
        |r| r.get(0),
    )
    .expect("read head")
}

/// Append until the chain head reaches `target`.
fn drive_sqlite(conn: &Connection, target: i64) {
    let mut n = 0;
    while head(conn) < target {
        n += 1;
        append_row(conn, n);
    }
    HIGH_WATER.fetch_max(target, Ordering::SeqCst);
}

#[test]
fn sqlite_genesisless_store_emits_no_watermark_7228() {
    let _g = CELL_LOCK.blocking_lock();
    let fdir = fresh_dir("sqlite-nogenesis-sink");
    let ddir = fresh_dir("sqlite-nogenesis-db");
    forensic::init(fdir.path(), None).expect("forensic init");
    let conn = open_db(ddir.path());
    drive_sqlite(&conn, ROWS_BEFORE_GENESIS_REMOVAL);
    conn.execute(
        "DELETE FROM signed_events WHERE sequence = ?1",
        [GENESIS_SEQUENCE],
    )
    .expect("remove genesis");
    assert_eq!(genesis_db_id(&conn).expect("genesis read"), None);
    drive_sqlite(&conn, target_head());
    forensic::shutdown();
    let rows = watermark_payloads(fdir.path());
    assert!(
        rows.is_empty(),
        "a genesis-less store must not emit an unattributable watermark; got {rows:?}"
    );
}

#[test]
fn sqlite_store_with_genesis_still_emits_identified_watermark_7228() {
    let _g = CELL_LOCK.blocking_lock();
    let fdir = fresh_dir("sqlite-genesis-sink");
    let ddir = fresh_dir("sqlite-genesis-db");
    forensic::init(fdir.path(), None).expect("forensic init");
    let conn = open_db(ddir.path());
    drive_sqlite(&conn, target_head());
    let expected = genesis_db_id(&conn)
        .expect("genesis read")
        .expect("genesis present");
    forensic::shutdown();
    let rows = watermark_payloads(fdir.path());
    assert!(!rows.is_empty(), "a store with genesis must still anchor");
    for row in &rows {
        assert_eq!(
            row.get("db_id").and_then(serde_json::Value::as_str),
            Some(expected.as_str()),
            "every emitted watermark must carry this store's db_id; row={row}"
        );
    }
}

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

#[cfg(feature = "sal-postgres")]
mod postgres_twin {
    use super::pg_barrier;
    use super::{
        CELL_LOCK, GENESIS_SEQUENCE, HIGH_WATER, ROWS_BEFORE_GENESIS_REMOVAL, forensic, fresh_dir,
        target_head, watermark_payloads,
    };
    use ai_memory::store::postgres::PostgresStore;
    use std::sync::atomic::Ordering;

    /// Scratch database name prefix for this file.
    const SCRATCH_PREFIX: &str = "ai_memory_7228wm";

    async fn pg_head(pg: &PostgresStore) -> i64 {
        sqlx::query_scalar("SELECT COALESCE(MAX(sequence), 0) FROM signed_events")
            .fetch_one(pg.pool())
            .await
            .expect("read pg head")
    }

    async fn drive_pg(pg: &PostgresStore, target: i64) {
        let mut n = 0;
        while pg_head(pg).await < target {
            n += 1;
            pg.emit_spawn_audit(&format!("argv0-{n}"), "7228-watermark")
                .await;
        }
        HIGH_WATER.fetch_max(target, Ordering::SeqCst);
    }

    async fn scratch_store(url: &str) -> (pg_barrier::ScratchDb, PostgresStore) {
        let scratch = pg_barrier::ScratchDb::create(url, SCRATCH_PREFIX)
            .await
            .expect("create scratch database");
        let pg = PostgresStore::connect(&scratch.url())
            .await
            .expect("connect scratch database");
        (scratch, pg)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_genesisless_store_emits_no_watermark_7228() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let _g = CELL_LOCK.lock().await;
        let (_scratch, pg) = scratch_store(&url).await;
        let fdir = fresh_dir("pg-nogenesis-sink");
        forensic::init(fdir.path(), None).expect("forensic init");
        drive_pg(&pg, ROWS_BEFORE_GENESIS_REMOVAL).await;
        sqlx::query("DELETE FROM signed_events WHERE sequence = $1")
            .bind(GENESIS_SEQUENCE)
            .execute(pg.pool())
            .await
            .expect("remove genesis");
        drive_pg(&pg, target_head()).await;
        forensic::shutdown();
        let rows = watermark_payloads(fdir.path());
        assert!(
            rows.is_empty(),
            "a genesis-less pg store must not emit an unattributable watermark; got {rows:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_store_with_genesis_still_emits_identified_watermark_7228() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let _g = CELL_LOCK.lock().await;
        let (_scratch, pg) = scratch_store(&url).await;
        let fdir = fresh_dir("pg-genesis-sink");
        forensic::init(fdir.path(), None).expect("forensic init");
        drive_pg(&pg, target_head()).await;
        let (gid, gagent, gpayload): (String, String, Vec<u8>) =
            sqlx::query_as(ai_memory::signed_events::GENESIS_ROW_SQL)
                .fetch_one(pg.pool())
                .await
                .expect("genesis row");
        let expected = ai_memory::signed_events::db_id_from_genesis_parts(&gid, &gagent, &gpayload);
        forensic::shutdown();
        let rows = watermark_payloads(fdir.path());
        assert!(
            !rows.is_empty(),
            "a pg store with genesis must still anchor"
        );
        for row in &rows {
            assert_eq!(
                row.get("db_id").and_then(serde_json::Value::as_str),
                Some(expected.as_str()),
                "every emitted watermark must carry this store's db_id; row={row}"
            );
        }
    }
}
