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

/// A text value in the genesis row's BLOB `payload_hash` column: SQLite stores
/// it as-is, and the genesis read then fails to decode it (a read ERROR, as
/// opposed to an absent row).
const UNREADABLE_GENESIS_HASH: &str = "not-a-blob";

/// #7239 / #7604 (3-agent vote (6def5ab6), Option B) - a genesis READ ERROR at an
/// emission-due append skips the watermark emission: the append still succeeds,
/// no db_id-less watermark row is written, the skip is counted (and logged), and
/// the NEXT emission-due append retries. The chain must never stall on it.
#[test]
fn sqlite_genesis_read_error_skips_the_watermark_and_the_append_succeeds_7239() {
    let _g = CELL_LOCK.blocking_lock();
    let fdir = fresh_dir("sqlite-readerr-sink");
    let ddir = fresh_dir("sqlite-readerr-db");
    forensic::init(fdir.path(), None).expect("forensic init");
    let conn = open_db(ddir.path());
    drive_sqlite(&conn, ROWS_BEFORE_GENESIS_REMOVAL);
    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1 WHERE sequence = ?2",
        rusqlite::params![UNREADABLE_GENESIS_HASH, GENESIS_SEQUENCE],
    )
    .expect("corrupt genesis payload_hash");
    assert!(
        genesis_db_id(&conn).is_err(),
        "the corrupted genesis must produce a read ERROR, not an absent row"
    );
    let skips_before = forensic::watermark_genesis_read_skips();
    let head_start = head(&conn);
    let limit = target_head() + 1;
    let mut n = 0;
    while head(&conn) < limit {
        n += 1;
        let head_before = head(&conn);
        let ev = SignedEvent {
            id: uuid::Uuid::new_v4().to_string(),
            agent_id: "alice".to_string(),
            event_type: "memory_link.created".to_string(),
            payload_hash: payload_hash(format!("read-error-{n}").as_bytes()),
            signature: None,
            attest_level: "unsigned".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            ..SignedEvent::default()
        };
        append_signed_event(&conn, &ev).unwrap_or_else(|e| {
            panic!("append {n} at head {head_before} must succeed past a genesis read error: {e:#}")
        });
        assert_eq!(
            head(&conn),
            head_before + 1,
            "every append must advance the chain head"
        );
    }
    HIGH_WATER.fetch_max(head(&conn), Ordering::SeqCst);
    forensic::shutdown();
    assert!(
        forensic::watermark_genesis_read_skips() > skips_before,
        "the skipped emission must be counted (and logged)"
    );
    // #7236 - a persistent fault backs the retry off to the next emission-due
    // append: the genesis is re-read (and the WARN fires) once per due window,
    // not on every later append.
    assert_skips_bounded_by_due_cadence(
        forensic::watermark_genesis_read_skips() - skips_before,
        head(&conn) - head_start,
    );
    let rows = watermark_payloads(fdir.path());
    assert!(
        rows.is_empty(),
        "no db_id-less watermark may be anchored on a genesis read error; got {rows:?}"
    );
}

/// #7236 - `skips` genesis read skips over `appends` appends must not exceed one
/// per `WATERMARK_INTERVAL` window (plus the window the run started in).
fn assert_skips_bounded_by_due_cadence(skips: u64, appends: i64) {
    let windows = u64::try_from(appends / forensic::WATERMARK_INTERVAL).expect("non-negative");
    assert!(
        skips >= 1 && skips <= windows + 1,
        "{skips} genesis read skips over {appends} appends: a persistent fault must retry once \
         per due window (at most {}), not on every append",
        windows + 1
    );
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

    /// #7239 / #7604 (3-agent vote (6def5ab6), Option B) - the postgres half: the
    /// same scenario as the sqlite cell with the same outcome. The genesis read
    /// runs in a SAVEPOINT, so its failure neither aborts the append's
    /// transaction nor stalls the chain; no watermark is anchored. The genesis
    /// read fails on the SERVER (#7677, see
    /// `inject_server_side_genesis_read_fault`), which aborts a transaction
    /// that has no savepoint.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_genesis_read_error_skips_the_watermark_and_the_append_succeeds_7239() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let _g = CELL_LOCK.lock().await;
        let (scratch, pg) = scratch_store(&url).await;
        let fdir = fresh_dir("pg-readerr-sink");
        forensic::init(fdir.path(), None).expect("forensic init");
        drive_pg(&pg, ROWS_BEFORE_GENESIS_REMOVAL).await;
        let faulted = inject_server_side_genesis_read_fault(&scratch, &pg).await;
        let _admin = pg;
        let pg = faulted;
        let skips_before = forensic::watermark_genesis_read_skips();
        let head_start = pg_head(&pg).await;
        let limit = target_head() + 1;
        let mut n = 0;
        while pg_head(&pg).await < limit {
            n += 1;
            let head_before = pg_head(&pg).await;
            pg.emit_spawn_audit(&format!("read-error-{n}"), "7239-watermark")
                .await;
            assert_eq!(
                pg_head(&pg).await,
                head_before + 1,
                "append {n} at head {head_before} must succeed past a genesis read error"
            );
        }
        HIGH_WATER.fetch_max(pg_head(&pg).await, Ordering::SeqCst);
        forensic::shutdown();
        assert!(
            forensic::watermark_genesis_read_skips() > skips_before,
            "the skipped emission must be counted (and logged)"
        );
        // #7236 - the retry is backed off to the next emission-due append on pg too.
        super::assert_skips_bounded_by_due_cadence(
            forensic::watermark_genesis_read_skips() - skips_before,
            pg_head(&pg).await - head_start,
        );
        let rows = watermark_payloads(fdir.path());
        assert!(
            rows.is_empty(),
            "no db_id-less watermark may be anchored on a genesis read error; got {rows:?}"
        );
    }

    /// #7677 - make the genesis read fail on the SERVER. The scratch database
    /// shadows the `bigint = integer` operator (the type pair of the literal
    /// `sequence = 1` in `GENESIS_ROW_SQL`) with a plpgsql function that raises
    /// for the genesis literal, and pins the database `search_path` so that
    /// `public` is searched before `pg_catalog`. The genesis statement then
    /// errors inside the append's transaction, which postgres aborts: without
    /// the SAVEPOINT around the read, every later statement of the append fails
    /// ("current transaction is aborted") and the append is lost. The append's
    /// own head read binds `bigint = bigint` and so is untouched. A client-side
    /// decode error (a NULL column) never aborts the server transaction and so
    /// could not pin the savepoint.
    ///
    /// The setting applies to NEW sessions, so the returned store is a fresh
    /// connection. The scratch database is dropped with its objects afterwards.
    async fn inject_server_side_genesis_read_fault(
        scratch: &pg_barrier::ScratchDb,
        admin: &PostgresStore,
    ) -> PostgresStore {
        let db = pg_barrier::quote_ident(scratch.name());
        let statements = [
            "CREATE FUNCTION public.sequence_eq_7677(bigint, integer) RETURNS boolean \
             LANGUAGE plpgsql AS $$ BEGIN \
             IF $2 = 1 THEN RAISE EXCEPTION 'injected genesis read fault 7677'; END IF; \
             RETURN $1 = $2::bigint; END $$"
                .to_string(),
            "CREATE OPERATOR public.= (LEFTARG = bigint, RIGHTARG = integer, \
             FUNCTION = public.sequence_eq_7677)"
                .to_string(),
            format!("ALTER DATABASE {db} SET search_path = public, pg_catalog"),
        ];
        for stmt in &statements {
            sqlx::query(stmt)
                .execute(admin.pool())
                .await
                .unwrap_or_else(|e| panic!("inject genesis read fault ({stmt}): {e}"));
        }
        let faulted = PostgresStore::connect(&scratch.url())
            .await
            .expect("connect with the genesis read fault active");
        let probe = sqlx::query(ai_memory::signed_events::GENESIS_ROW_SQL)
            .fetch_optional(faulted.pool())
            .await;
        assert!(
            probe.is_err(),
            "the injected fault must make the genesis read fail on the server"
        );
        faulted
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
