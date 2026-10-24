// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7241 - the off-table audit watermark (#1850) must be recorded only AFTER
//! the appending transaction COMMITS, on both backends.
//!
//! The defect: both append chokepoints (the sqlite signed-events writer and the
//! postgres in-tx writer) claimed the process-global throttle and wrote the
//! forensic `audit_watermark` row INSIDE the appending transaction. When that
//! transaction later rolled back, the sink kept an anchor for a row that never
//! existed:
//! - the in-DB head sat below the anchored head, so the verifier reported a
//!   false tail TRUNCATION (`TruncationCheck::Detected`);
//! - the next append reused the same sequence with a different row, the
//!   throttle had already been claimed so it was not re-anchored, and the
//!   head-hash recompute reported a false tamper (`HeadHashCheck::Mismatch`).
//!
//! Pins, on both backends:
//! - a rolled-back append that was due for a watermark leaves NO anchor above
//!   the surviving head and no truncation / mismatch verdict;
//! - the committed append that reuses the sequence IS anchored (with its own
//!   hash), so the throttle was not burned by the rollback;
//! - the main committed write paths still anchor at the interval (guards
//!   against a commit site that drops the pending anchor: fail-open).
//!
//! The throttle (`LAST_WATERMARKED_SEQ`) and the forensic sink are
//! process-global, so every cell serialises through one lock and drives its
//! chain until the NEXT append is due rather than to a fixed head.

#![allow(clippy::missing_panics_doc)]

use std::path::{Path, PathBuf};

use ai_memory::governance::audit as forensic;
use ai_memory::governance::rules_store::{self, Rule};
use ai_memory::models::{Memory, MemoryKind, Tier};
use ai_memory::signed_events::{
    HeadHashCheck, SignedEvent, TruncationCheck, append_signed_event, append_signed_event_no_tx,
    genesis_db_id, payload_hash, verify_audit_trail,
};
use rusqlite::Connection;

/// Serialises every cell (the forensic sink and the throttle are process-global).
static CELL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Number of watermark intervals each main-path cell crosses.
const MAIN_PATH_CROSSINGS: usize = 2;

/// Rule id used by the governance-rules write-path cell.
const RULE_ID: &str = "R7241";

/// Seed of the deterministic operator signing key for the rules cell.
const RULE_KEY_SEED: [u8; 32] = [7u8; 32];

/// Operator principal recorded on the signed rule toggles.
const RULE_OPERATOR: &str = "operator";

/// Agent id stamped on the test rows.
const ROW_AGENT: &str = "alice";

/// Event type of the test rows.
const ROW_EVENT_TYPE: &str = "memory_link.created";

/// Attestation level of the test rows.
const ROW_ATTEST: &str = "unsigned";

/// Tempdirs under `.local-runs/` (project no-`/tmp` HARD RULE).
fn fresh_dir(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-7241-watermark-after-commit");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

/// Assert the verifier gives neither a truncation nor a head-hash mismatch.
fn assert_no_false_verdict(truncation: &TruncationCheck, head_hash: &HeadHashCheck, context: &str) {
    assert!(
        !matches!(truncation, TruncationCheck::Detected { .. }),
        "{context}: a rolled-back append must not convict the store of truncation; got {truncation:?}"
    );
    assert!(
        !matches!(head_hash, HeadHashCheck::Mismatch { .. }),
        "{context}: a rolled-back append must not convict the head row of tampering; got {head_hash:?}"
    );
}

/// Database file name inside each cell's scratch directory.
const DB_FILE: &str = "audit.db";

/// Namespace of the memories the erasure path deletes.
const ERASE_NAMESPACE: &str = "issue-7241-erase";

/// A memory owned by `agent`, for the nested erasure path (`delete`).
fn probe_memory(agent: &str, title: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Long,
        namespace: ERASE_NAMESPACE.to_string(),
        title: title.to_string(),
        content: "body".to_string(),
        source: "test".to_string(),
        memory_kind: MemoryKind::Observation,
        created_at: now.clone(),
        updated_at: now,
        metadata: serde_json::json!({ "agent_id": agent }),
        ..Default::default()
    }
}

fn open_db(dir: &Path) -> Connection {
    let path = dir.join(DB_FILE);
    drop(ai_memory::db::open(&path).expect("init db"));
    ai_memory::db::open(&path).expect("open db")
}

fn row_event(label: &str) -> SignedEvent {
    SignedEvent {
        id: uuid::Uuid::new_v4().to_string(),
        agent_id: ROW_AGENT.to_string(),
        event_type: ROW_EVENT_TYPE.to_string(),
        payload_hash: payload_hash(label.as_bytes()),
        signature: None,
        attest_level: ROW_ATTEST.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        ..SignedEvent::default()
    }
}

fn head(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM signed_events",
        [],
        |r| r.get(0),
    )
    .expect("read head")
}

/// Commit rows until the NEXT append is due for a watermark.
fn drive_sqlite_until_due(conn: &Connection) {
    let mut n = 0_u64;
    while !forensic::watermark_emission_due(head(conn) + 1) {
        n += 1;
        append_signed_event(conn, &row_event(&format!("drive-{n}"))).expect("append");
    }
}

fn sqlite_db_id(conn: &Connection) -> String {
    genesis_db_id(conn)
        .expect("genesis read")
        .expect("genesis present")
}

/// Highest anchored sequence for `db_id` in the live sink (0 when none).
fn anchored_seq(db_id: &str) -> i64 {
    forensic::last_audit_watermark(Some(db_id)).map_or(0, |(seq, _)| seq)
}

#[test]
fn sqlite_rolled_back_due_append_leaves_no_anchor_7241() {
    let _g = CELL_LOCK.blocking_lock();
    let fdir = fresh_dir("sqlite-rollback-sink");
    let ddir = fresh_dir("sqlite-rollback-db");
    forensic::init(fdir.path(), None).expect("forensic init");
    let conn = open_db(ddir.path());
    drive_sqlite_until_due(&conn);
    let survivor = head(&conn);
    let db_id = sqlite_db_id(&conn);

    // The due append runs inside a transaction that then ROLLS BACK.
    {
        let tx = conn.unchecked_transaction().expect("begin doomed tx");
        let _rolled_back =
            append_signed_event_no_tx(&tx, &row_event("doomed")).expect("append in doomed tx");
        tx.rollback().expect("rollback");
    }
    assert_eq!(head(&conn), survivor, "the rollback must discard the row");
    let anchored = anchored_seq(&db_id);
    assert!(
        anchored <= survivor,
        "no anchor may sit above the surviving head {survivor}; anchored {anchored}"
    );
    let report = verify_audit_trail(&conn, None, None).expect("verify after rollback");
    assert_no_false_verdict(&report.truncation, &report.head_hash, "sqlite rollback");

    // A DIFFERENT committed row reuses the sequence: it must be anchored.
    append_signed_event(&conn, &row_event("survivor")).expect("append after rollback");
    assert_eq!(head(&conn), survivor + 1);
    assert_eq!(
        anchored_seq(&db_id),
        survivor + 1,
        "the committed append at the interval must be anchored (throttle not burned)"
    );
    let report = verify_audit_trail(&conn, None, None).expect("verify after re-append");
    assert_no_false_verdict(&report.truncation, &report.head_hash, "sqlite re-append");
    forensic::shutdown();
}

/// A text value in the genesis row's BLOB `payload_hash` column: the genesis
/// read then fails to decode (a read ERROR, not an absent row).
const UNREADABLE_GENESIS_HASH: &str = "not-a-blob";

/// Sequence of the genesis row.
const GENESIS_SEQUENCE: i64 = 1;

/// #7746 - a genesis-read skip is a post-commit side effect (#7241 discipline):
/// a skip whose append transaction ROLLS BACK neither counts nor claims the
/// retry backoff, so the next emission-due append re-reads the genesis; the
/// counter equals the number of COMMITTED skips.
#[test]
fn sqlite_rolled_back_genesis_skip_neither_counts_nor_claims_backoff_7746() {
    let _g = CELL_LOCK.blocking_lock();
    let fdir = fresh_dir("sqlite-skip-rollback-sink");
    let ddir = fresh_dir("sqlite-skip-rollback-db");
    forensic::init(fdir.path(), None).expect("forensic init");
    let conn = open_db(ddir.path());
    drive_sqlite_until_due(&conn);
    let survivor = head(&conn);
    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1 WHERE sequence = ?2",
        rusqlite::params![UNREADABLE_GENESIS_HASH, GENESIS_SEQUENCE],
    )
    .expect("corrupt genesis payload_hash");
    assert!(genesis_db_id(&conn).is_err(), "genesis must be unreadable");
    let skips_before = forensic::watermark_genesis_read_skips();

    // The due append skips on the genesis read error, then its transaction
    // ROLLS BACK.
    {
        let tx = conn.unchecked_transaction().expect("begin doomed tx");
        let pending = append_signed_event_no_tx(&tx, &row_event("doomed-skip"))
            .expect("the skip must not fail the append");
        tx.rollback().expect("rollback");
        pending.discard();
    }
    assert_eq!(head(&conn), survivor, "the rollback must discard the row");
    assert_eq!(
        forensic::watermark_genesis_read_skips(),
        skips_before,
        "a skip whose append rolled back must not be counted"
    );
    assert!(
        forensic::watermark_emission_due(survivor + 1),
        "a rolled-back skip must not claim the retry backoff: the next due append re-reads the genesis"
    );

    // The re-appended due sequence skips again and this time COMMITS: one
    // committed skip, one count, and the backoff is now claimed.
    append_signed_event(&conn, &row_event("committed-skip")).expect("committed skip");
    assert_eq!(head(&conn), survivor + 1);
    assert_eq!(
        forensic::watermark_genesis_read_skips(),
        skips_before + 1,
        "the counter equals the number of COMMITTED skips"
    );
    assert!(
        !forensic::watermark_emission_due(survivor + 2),
        "a committed skip claims the retry backoff for one window (#7236)"
    );
    forensic::shutdown();
}

/// Appends one transaction carries in the #7755 multi-append cells.
const MULTI_APPENDS: usize = 10;

/// #7755 - inside ONE transaction the genesis-read skip is claimed once per due
/// window: the first due append re-reads the genesis and records the skip, the
/// later appends of the same transaction (whose committed backoff is not yet
/// visible) are suppressed by the tentative in-transaction marker. One genesis
/// re-read, one counted skip, however many rows the transaction appends.
#[test]
fn sqlite_multi_append_tx_counts_one_genesis_skip_7755() {
    let _g = CELL_LOCK.blocking_lock();
    let fdir = fresh_dir("sqlite-multi-skip-sink");
    let ddir = fresh_dir("sqlite-multi-skip-db");
    forensic::init(fdir.path(), None).expect("forensic init");
    let conn = open_db(ddir.path());
    drive_sqlite_until_due(&conn);
    let survivor = head(&conn);
    conn.execute(
        "UPDATE signed_events SET payload_hash = ?1 WHERE sequence = ?2",
        rusqlite::params![UNREADABLE_GENESIS_HASH, GENESIS_SEQUENCE],
    )
    .expect("corrupt genesis payload_hash");
    assert!(genesis_db_id(&conn).is_err(), "genesis must be unreadable");
    let skips_before = forensic::watermark_genesis_read_skips();

    let tx = conn.unchecked_transaction().expect("begin multi tx");
    let mut pending = forensic::PendingAuditAnchor::none();
    let mut genesis_rereads = 0_usize;
    for n in 0..MULTI_APPENDS {
        if forensic::watermark_emission_due(head(&tx) + 1) {
            genesis_rereads += 1;
        }
        let appended = append_signed_event_no_tx(&tx, &row_event(&format!("multi-{n}")))
            .expect("the skip must not fail the append");
        pending = pending.merge(appended);
    }
    tx.commit().expect("commit multi tx");
    pending.emit_after_commit();

    let appended_rows = i64::try_from(MULTI_APPENDS).expect("append count fits i64");
    assert_eq!(head(&conn), survivor + appended_rows);
    assert_eq!(
        genesis_rereads, 1,
        "one genesis re-read per due window inside a transaction (#7236)"
    );
    assert_eq!(
        forensic::watermark_genesis_read_skips(),
        skips_before + 1,
        "one counted skip per due window inside a transaction (#7755)"
    );
    forensic::shutdown();
}

#[test]
fn sqlite_main_write_paths_still_anchor_7241() {
    let _g = CELL_LOCK.blocking_lock();
    let fdir = fresh_dir("sqlite-main-sink");
    let ddir = fresh_dir("sqlite-main-db");
    forensic::init(fdir.path(), None).expect("forensic init");
    let conn = open_db(ddir.path());
    rules_store::insert(
        &conn,
        &Rule {
            id: RULE_ID.into(),
            kind: "bash".into(),
            matcher: r#"{"command_regex":"x"}"#.into(),
            severity: "refuse".into(),
            reason: "7241".into(),
            namespace: "_global".into(),
            created_by: "test".into(),
            created_at: 0,
            enabled: true,
            signature: None,
            attest_level: ROW_ATTEST.into(),
        },
    )
    .expect("insert rule");
    let key = ed25519_dalek::SigningKey::from_bytes(&RULE_KEY_SEED);
    drive_sqlite_until_due(&conn);
    let db_id = sqlite_db_id(&conn);

    // Path 1: the self-committing wrapper.
    for crossing in 0..MAIN_PATH_CROSSINGS {
        drive_sqlite_until_due(&conn);
        let before = head(&conn);
        append_signed_event(&conn, &row_event(&format!("wrapper-{crossing}"))).expect("append");
        assert!(
            anchored_seq(&db_id) > before,
            "append_signed_event at the interval must anchor (crossing {crossing})"
        );
    }

    // Path 2: a store-owned transaction with nested appends (rule toggle +
    // policy-version advance), committed by the owner.
    let mut enabled = true;
    for crossing in 0..MAIN_PATH_CROSSINGS {
        drive_sqlite_until_due(&conn);
        let before = head(&conn);
        enabled = !enabled;
        let changed = rules_store::set_enabled_signed(&conn, RULE_ID, enabled, &key, RULE_OPERATOR)
            .expect("toggle rule");
        assert!(changed, "the rule toggle must land (crossing {crossing})");
        assert!(head(&conn) > before, "the rule toggle must append");
        assert!(
            anchored_seq(&db_id) > before,
            "set_enabled_signed at the interval must anchor (crossing {crossing})"
        );
    }
    // Path 3: a nested erasure funnel on an autocommit connection (no
    // WriteTxn frame): the crypto-erase attestation is emitted at once.
    for crossing in 0..MAIN_PATH_CROSSINGS {
        let victim = ai_memory::db::insert(
            &conn,
            &probe_memory(ROW_AGENT, &format!("erase-{crossing}")),
        )
        .expect("insert erase probe");
        drive_sqlite_until_due(&conn);
        let before = head(&conn);
        assert!(ai_memory::db::delete(&conn, &victim).expect("delete erase probe"));
        assert!(
            head(&conn) > before,
            "the delete must append its erasure attestation"
        );
        assert!(
            anchored_seq(&db_id) > before,
            "an autocommit delete at the interval must anchor (crossing {crossing})"
        );
    }
    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert_no_false_verdict(&report.truncation, &report.head_hash, "sqlite main paths");
    forensic::shutdown();
}

/// The store `delete` appends the crypto-erase attestation deep inside its
/// `WriteTxn`: the frame must emit the anchor on COMMIT.
#[cfg(feature = "sal")]
#[test]
fn sqlite_store_delete_frame_anchors_7241() {
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    let _g = CELL_LOCK.blocking_lock();
    let fdir = fresh_dir("sqlite-frame-sink");
    let ddir = fresh_dir("sqlite-frame-db");
    forensic::init(fdir.path(), None).expect("forensic init");
    let conn = open_db(ddir.path());
    drive_sqlite_until_due(&conn);
    let db_id = sqlite_db_id(&conn);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let store = SqliteStore::open(ddir.path().join(DB_FILE)).expect("open store");
    let ctx = CallerContext::for_agent(ROW_AGENT);
    for crossing in 0..MAIN_PATH_CROSSINGS {
        let victim = rt
            .block_on(store.store(&ctx, &probe_memory(ROW_AGENT, &format!("frame-{crossing}"))))
            .expect("store erase probe");
        drive_sqlite_until_due(&conn);
        let before = head(&conn);
        rt.block_on(store.delete(&ctx, &victim))
            .expect("delete erase probe");
        assert!(
            head(&conn) > before,
            "the delete must append its erasure attestation"
        );
        assert!(
            anchored_seq(&db_id) > before,
            "the store delete at the interval must anchor (crossing {crossing})"
        );
    }
    let report = verify_audit_trail(&conn, None, None).expect("verify");
    assert_no_false_verdict(&report.truncation, &report.head_hash, "sqlite frame path");
    forensic::shutdown();
}

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

#[cfg(feature = "sal-postgres")]
mod postgres_twin {
    use super::pg_barrier;
    use super::{
        CELL_LOCK, MAIN_PATH_CROSSINGS, anchored_seq, assert_no_false_verdict, forensic, fresh_dir,
    };
    use ai_memory::models::{Memory, MemoryKind, Tier};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};
    use ai_memory::wake_hub::delegation_verifier::{ALLOWLIST_FILE_VERSION, AllowlistFile};

    /// Scratch database name prefix for this file.
    const SCRATCH_PREFIX: &str = "ai_memory_7241wm";

    /// Spawn-audit caller label for the driven rows.
    const SPAWN_CALLER: &str = "7241-watermark";

    /// Agent that owns the reclassified memory.
    const RECLASSIFY_AGENT: &str = "ai:7241-reclassifier";

    /// Namespace of the reclassified memory.
    const RECLASSIFY_NAMESPACE: &str = "issue-7241";

    /// Fault table: a sequence listed here fails its transaction AT COMMIT.
    const FAIL_TABLE_DDL: &str = "CREATE TABLE public.fail_7241 (seq BIGINT PRIMARY KEY)";

    /// Deferred check that raises at COMMIT for a listed sequence.
    const FAIL_FN_DDL: &str = "CREATE FUNCTION public.fail_7241_check() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
         IF EXISTS (SELECT 1 FROM public.fail_7241 WHERE seq = NEW.sequence) THEN \
         RAISE EXCEPTION 'issue 7241 forced commit failure'; END IF; RETURN NULL; END $$";

    /// The constraint trigger fires at COMMIT (after the in-tx append returned).
    const FAIL_TRIGGER_DDL: &str = "CREATE CONSTRAINT TRIGGER fail_7241_at_commit \
         AFTER INSERT ON signed_events DEFERRABLE INITIALLY DEFERRED \
         FOR EACH ROW EXECUTE FUNCTION public.fail_7241_check()";

    async fn pg_head(pg: &PostgresStore) -> i64 {
        sqlx::query_scalar("SELECT COALESCE(MAX(sequence), 0) FROM signed_events")
            .fetch_one(pg.pool())
            .await
            .expect("read pg head")
    }

    /// Commit spawn-audit rows until the NEXT append is due for a watermark.
    async fn drive_pg_until_due(pg: &PostgresStore) {
        let mut n = 0_u64;
        while !forensic::watermark_emission_due(pg_head(pg).await + 1) {
            n += 1;
            pg.emit_spawn_audit(&format!("argv0-{n}"), SPAWN_CALLER)
                .await;
        }
    }

    async fn pg_db_id(pg: &PostgresStore) -> String {
        let (gid, gagent, gpayload): (String, String, Vec<u8>) =
            sqlx::query_as(ai_memory::signed_events::GENESIS_ROW_SQL)
                .fetch_one(pg.pool())
                .await
                .expect("genesis row");
        ai_memory::signed_events::db_id_from_genesis_parts(&gid, &gagent, &gpayload)
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
    async fn pg_rolled_back_due_append_leaves_no_anchor_7241() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let _g = CELL_LOCK.lock().await;
        let (_scratch, pg) = scratch_store(&url).await;
        let fdir = fresh_dir("pg-rollback-sink");
        forensic::init(fdir.path(), None).expect("forensic init");
        for ddl in [FAIL_TABLE_DDL, FAIL_FN_DDL, FAIL_TRIGGER_DDL] {
            sqlx::raw_sql(ddl)
                .execute(pg.pool())
                .await
                .expect("install commit-time fault");
        }
        drive_pg_until_due(&pg).await;
        let survivor = pg_head(&pg).await;
        let db_id = pg_db_id(&pg).await;

        // The due append's transaction fails AT COMMIT (the error is swallowed
        // by the spawn-audit writer, exactly as in production).
        sqlx::query("INSERT INTO public.fail_7241 (seq) VALUES ($1)")
            .bind(survivor + 1)
            .execute(pg.pool())
            .await
            .expect("arm fault");
        pg.emit_spawn_audit("argv0-doomed", SPAWN_CALLER).await;
        sqlx::query("DELETE FROM public.fail_7241")
            .execute(pg.pool())
            .await
            .expect("disarm fault");
        assert_eq!(
            pg_head(&pg).await,
            survivor,
            "the failed commit must discard the row"
        );
        let anchored = anchored_seq(&db_id);
        assert!(
            anchored <= survivor,
            "no anchor may sit above the surviving head {survivor}; anchored {anchored}"
        );
        let report = pg
            .verify_audit_trail(None, None)
            .await
            .expect("verify after rollback");
        assert_no_false_verdict(&report.truncation, &report.head_hash, "pg rollback");

        // A DIFFERENT committed row reuses the sequence: it must be anchored.
        pg.emit_spawn_audit("argv0-survivor", SPAWN_CALLER).await;
        assert_eq!(pg_head(&pg).await, survivor + 1);
        assert_eq!(
            anchored_seq(&db_id),
            survivor + 1,
            "the committed append at the interval must be anchored (throttle not burned)"
        );
        let report = pg
            .verify_audit_trail(None, None)
            .await
            .expect("verify after re-append");
        assert_no_false_verdict(&report.truncation, &report.head_hash, "pg re-append");
        forensic::shutdown();
    }

    /// #7746 - make the genesis read fail on the SERVER (the #7677 injector:
    /// shadow `bigint = integer` for the genesis literal, pin the database
    /// `search_path`). The setting applies to NEW sessions, so the returned
    /// store is a fresh connection.
    async fn inject_genesis_read_fault(
        scratch: &pg_barrier::ScratchDb,
        admin: &PostgresStore,
    ) -> PostgresStore {
        let db = pg_barrier::quote_ident(scratch.name());
        let statements = [
            "CREATE FUNCTION public.sequence_eq_7746(bigint, integer) RETURNS boolean \
             LANGUAGE plpgsql AS $$ BEGIN \
             IF $2 = 1 THEN RAISE EXCEPTION 'injected genesis read fault 7746'; END IF; \
             RETURN $1 = $2::bigint; END $$"
                .to_string(),
            "CREATE OPERATOR public.= (LEFTARG = bigint, RIGHTARG = integer, \
             FUNCTION = public.sequence_eq_7746)"
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
            "the injected fault must fail the genesis read"
        );
        faulted
    }

    /// #7746 - postgres twin of the sqlite cell: a genesis-read skip whose
    /// transaction fails AT COMMIT neither counts nor claims the retry backoff.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_rolled_back_genesis_skip_neither_counts_nor_claims_backoff_7746() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let _g = CELL_LOCK.lock().await;
        let (scratch, admin) = scratch_store(&url).await;
        let fdir = fresh_dir("pg-skip-rollback-sink");
        forensic::init(fdir.path(), None).expect("forensic init");
        for ddl in [FAIL_TABLE_DDL, FAIL_FN_DDL, FAIL_TRIGGER_DDL] {
            sqlx::raw_sql(ddl)
                .execute(admin.pool())
                .await
                .expect("install commit-time fault");
        }
        drive_pg_until_due(&admin).await;
        let survivor = pg_head(&admin).await;
        let pg = inject_genesis_read_fault(&scratch, &admin).await;
        let skips_before = forensic::watermark_genesis_read_skips();

        // The due append skips on the genesis read error, then its transaction
        // fails AT COMMIT.
        sqlx::query("INSERT INTO public.fail_7241 (seq) VALUES ($1)")
            .bind(survivor + 1)
            .execute(admin.pool())
            .await
            .expect("arm fault");
        pg.emit_spawn_audit("argv0-doomed-skip", SPAWN_CALLER).await;
        sqlx::query("DELETE FROM public.fail_7241")
            .execute(admin.pool())
            .await
            .expect("disarm fault");
        assert_eq!(
            pg_head(&admin).await,
            survivor,
            "the failed commit must discard the row"
        );
        assert_eq!(
            forensic::watermark_genesis_read_skips(),
            skips_before,
            "a skip whose append rolled back must not be counted"
        );
        assert!(
            forensic::watermark_emission_due(survivor + 1),
            "a rolled-back skip must not claim the retry backoff"
        );

        // The re-appended due sequence skips again and COMMITS.
        pg.emit_spawn_audit("argv0-committed-skip", SPAWN_CALLER)
            .await;
        assert_eq!(pg_head(&admin).await, survivor + 1);
        assert_eq!(
            forensic::watermark_genesis_read_skips(),
            skips_before + 1,
            "the counter equals the number of COMMITTED skips"
        );
        assert!(
            !forensic::watermark_emission_due(survivor + 2),
            "a committed skip claims the retry backoff for one window (#7236)"
        );
        forensic::shutdown();
    }

    /// #7755 - postgres twin: one transaction that appends several signed
    /// events (the hub-cache allowlist audit) under a persistent genesis read
    /// fault counts ONE skip, not one per row past the due point.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_multi_append_tx_counts_one_genesis_skip_7755() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let _g = CELL_LOCK.lock().await;
        let (scratch, admin) = scratch_store(&url).await;
        let fdir = fresh_dir("pg-multi-skip-sink");
        forensic::init(fdir.path(), None).expect("forensic init");
        drive_pg_until_due(&admin).await;
        let survivor = pg_head(&admin).await;
        let pg = inject_genesis_read_fault(&scratch, &admin).await;
        let skips_before = forensic::watermark_genesis_read_skips();

        let agents: Vec<serde_json::Value> = (0..super::MULTI_APPENDS)
            .map(|n| {
                serde_json::json!({
                    "agent_id": format!("ai:7755-agent-{n}"),
                    "pubkey_b64": "AAAA",
                    "bound_at": "2026-10-18T00:00:00+00:00",
                })
            })
            .collect();
        let next: AllowlistFile = serde_json::from_value(serde_json::json!({
            "version": ALLOWLIST_FILE_VERSION,
            "refreshed_at": "2026-10-18T00:00:00+00:00",
            "agents": agents,
        }))
        .expect("allowlist file");
        pg.audit_hub_cache(None, &next)
            .await
            .expect("the skip must not fail the audit transaction");

        let appended_rows = i64::try_from(super::MULTI_APPENDS).expect("append count fits i64");
        assert_eq!(pg_head(&admin).await, survivor + appended_rows);
        assert_eq!(
            forensic::watermark_genesis_read_skips(),
            skips_before + 1,
            "one counted skip per due window inside a transaction (#7755)"
        );
        forensic::shutdown();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_main_write_paths_still_anchor_7241() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let _g = CELL_LOCK.lock().await;
        let (_scratch, pg) = scratch_store(&url).await;
        let fdir = fresh_dir("pg-main-sink");
        forensic::init(fdir.path(), None).expect("forensic init");
        let ctx = CallerContext::for_agent(RECLASSIFY_AGENT);
        let now = chrono::Utc::now().to_rfc3339();
        let mem = Memory {
            id: uuid::Uuid::new_v4().to_string(),
            tier: Tier::Long,
            namespace: RECLASSIFY_NAMESPACE.to_string(),
            title: "7241 reclassify probe".to_string(),
            content: "body".to_string(),
            source: "test".to_string(),
            memory_kind: MemoryKind::Observation,
            created_at: now.clone(),
            updated_at: now,
            metadata: serde_json::json!({ "agent_id": RECLASSIFY_AGENT }),
            ..Default::default()
        };
        let id = pg.store(&ctx, &mem).await.expect("store probe row");
        drive_pg_until_due(&pg).await;
        let db_id = pg_db_id(&pg).await;

        // Path 1: the pool wrapper (begin, append, commit).
        for crossing in 0..MAIN_PATH_CROSSINGS {
            drive_pg_until_due(&pg).await;
            let before = pg_head(&pg).await;
            pg.emit_spawn_audit(&format!("argv0-main-{crossing}"), SPAWN_CALLER)
                .await;
            assert!(
                anchored_seq(&db_id) > before,
                "the pool append path at the interval must anchor (crossing {crossing})"
            );
        }

        // Path 2: a store method that owns its transaction and appends in it.
        let mut to_claim = true;
        for crossing in 0..MAIN_PATH_CROSSINGS {
            drive_pg_until_due(&pg).await;
            let before = pg_head(&pg).await;
            let kind = if to_claim {
                MemoryKind::Claim
            } else {
                MemoryKind::Observation
            };
            to_claim = !to_claim;
            let changed = pg
                .reclassify_memory_kind(&ctx, &id, kind)
                .await
                .expect("reclassify");
            assert!(
                changed,
                "the reclassification must land (crossing {crossing})"
            );
            assert!(
                pg_head(&pg).await > before,
                "the reclassification must append"
            );
            assert!(
                anchored_seq(&db_id) > before,
                "reclassify_memory_kind at the interval must anchor (crossing {crossing})"
            );
        }
        // Path 3: a nested erasure funnel. The crypto-erase attestation is
        // appended inside the hard-delete helper; `delete` commits and emits.
        for crossing in 0..MAIN_PATH_CROSSINGS {
            let victim = pg
                .store(
                    &ctx,
                    &super::probe_memory(RECLASSIFY_AGENT, &format!("erase-{crossing}")),
                )
                .await
                .expect("store erase probe");
            drive_pg_until_due(&pg).await;
            let before = pg_head(&pg).await;
            pg.delete(&ctx, &victim).await.expect("delete erase probe");
            assert!(
                pg_head(&pg).await > before,
                "the delete must append its erasure attestation"
            );
            assert!(
                anchored_seq(&db_id) > before,
                "delete at the interval must anchor (crossing {crossing})"
            );
        }
        let report = pg.verify_audit_trail(None, None).await.expect("verify");
        assert_no_false_verdict(&report.truncation, &report.head_hash, "pg main paths");
        forensic::shutdown();
    }
}
