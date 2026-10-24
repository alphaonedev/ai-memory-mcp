// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #7241 (L2) - pins the documented rollback behaviour of the audit-head
//! WITNESS slot claim.
//!
//! Unlike the #1850 watermark (claimed only after COMMIT), the witness slot
//! (`LAST_WITNESSED_SEQ`) is still claimed INSIDE the appending transaction,
//! because the signed witness checkpoint row is inserted in that same
//! transaction. A rolled-back append that was due for a witness therefore
//! burns the slot: the interval that the rollback discarded gets no witness,
//! and the next witness is emitted one full `WATERMARK_INTERVAL` later (up to
//! about two intervals of committed rows go unwitnessed).
//!
//! This is bounded under-emission only. The checkpoint row rolled back with
//! the transaction and the off-table mirror is written after COMMIT, so the
//! verifier never sees a witness above the surviving head (no false
//! truncation, no false head-hash mismatch).
//!
//! decision: keep the in-transaction witness slot claim over moving it
//! after COMMIT, because the checkpoint row and the claim are one unit (a
//! post-commit claim would let two concurrent transactions each insert a
//! witness row for the same boundary) and the bounded under-emission is
//! already the documented trade-off. The cells below pin that behaviour so a
//! later change to it is deliberate.
//!
//! The witness slot, the key env vars and the forensic sink are
//! process-global: every cell serialises through one lock.

#![allow(clippy::missing_panics_doc)]

use std::path::{Path, PathBuf};

use ai_memory::governance::audit as witness;
use ai_memory::signed_events::{
    SignedEvent, append_signed_event, append_signed_event_no_tx, payload_hash,
};
use rusqlite::Connection;

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

/// Serialises every cell (the witness slot, env and sink are process-global).
static CELL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Agent id of the driven rows.
const ROW_AGENT: &str = "alice";

/// Event type of the driven rows.
const ROW_EVENT_TYPE: &str = "memory_link.created";

/// Attestation level of the driven rows.
const ROW_ATTEST: &str = "unsigned";

/// Tempdirs under `.local-runs/` (project no-`/tmp` HARD RULE), owner-only.
fn fresh_dir(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-7241-witness-rollback");
    key_dir_sandbox::mkdir_0700(&root);
    let dir = tempfile::Builder::new()
        .prefix(&format!("{label}-"))
        .tempdir_in(&root)
        .expect("tempdir under .local-runs");
    key_dir_sandbox::mkdir_0700(dir.path());
    dir
}

/// Enrol a fresh witness key into `dir` and point the witness env at it.
fn enrol_witness(dir: &Path) {
    let kp = ai_memory::identity::keypair::generate(witness::WITNESS_KEY_LABEL).expect("generate");
    ai_memory::identity::keypair::save(&kp, dir).expect("save witness key");
    // SAFETY: every cell holds CELL_LOCK, so no other thread reads the env.
    unsafe {
        std::env::set_var(witness::WITNESS_KEY_DIR_ENV, dir);
        std::env::set_var(witness::WITNESS_PUBKEY_ENV, kp.public_base64());
    }
}

fn clear_witness_env() {
    // SAFETY: every cell holds CELL_LOCK, so no other thread reads the env.
    unsafe {
        std::env::remove_var(witness::WITNESS_KEY_DIR_ENV);
        std::env::remove_var(witness::WITNESS_PUBKEY_ENV);
    }
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

fn witness_count(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM checkpoints WHERE namespace = ?1",
        [witness::WITNESS_CHECKPOINT_NAMESPACE],
        |r| r.get(0),
    )
    .expect("count witness checkpoints")
}

/// Commit rows until the NEXT append is due for a witness.
fn drive_until_witness_due(conn: &Connection) {
    let mut n = 0_u64;
    while !witness::witness_interval_reached(head(conn) + 1) {
        n += 1;
        append_signed_event(conn, &row_event(&format!("drive-{n}"))).expect("append");
    }
}

#[test]
fn sqlite_rolled_back_due_append_burns_the_witness_slot_7241() {
    let _g = CELL_LOCK.blocking_lock();
    let fdir = fresh_dir("sqlite-sink");
    let kdir = fresh_dir("sqlite-keys");
    let ddir = fresh_dir("sqlite-db");
    witness::init(fdir.path(), None).expect("forensic init");
    enrol_witness(kdir.path());
    let path = ddir.path().join("audit.db");
    drop(ai_memory::db::open(&path).expect("init db"));
    let conn = ai_memory::db::open(&path).expect("open db");
    drive_until_witness_due(&conn);
    let survivor = head(&conn);
    let due_sequence = survivor + 1;
    assert_eq!(witness_count(&conn), 0, "no witness before the due append");

    // The due append runs in a transaction that then ROLLS BACK.
    {
        let tx = conn.unchecked_transaction().expect("begin doomed tx");
        let _rolled_back =
            append_signed_event_no_tx(&tx, &row_event("doomed")).expect("append in doomed tx");
        tx.rollback().expect("rollback");
    }
    assert_eq!(head(&conn), survivor, "the rollback must discard the row");
    assert_eq!(
        witness_count(&conn),
        0,
        "the witness checkpoint row rolls back with the transaction"
    );
    assert!(
        !witness::witness_interval_reached(due_sequence),
        "documented behaviour: the rollback burned the in-transaction witness slot"
    );

    // The committed append that reuses the sequence is NOT witnessed, and no
    // witness appears until a full interval past the burned slot.
    append_signed_event(&conn, &row_event("survivor")).expect("append after rollback");
    assert_eq!(head(&conn), due_sequence);
    while head(&conn) < due_sequence + witness::WATERMARK_INTERVAL - 1 {
        append_signed_event(&conn, &row_event("skipped")).expect("append in skipped interval");
    }
    assert_eq!(
        witness_count(&conn),
        0,
        "bounded under-emission: the interval after the burned slot is unwitnessed"
    );
    append_signed_event(&conn, &row_event("next-interval")).expect("append at next interval");
    assert_eq!(
        witness_count(&conn),
        1,
        "the witness resumes one WATERMARK_INTERVAL after the burned slot"
    );
    clear_witness_env();
    witness::shutdown();
}

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

#[cfg(feature = "sal-postgres")]
mod postgres_twin {
    use super::pg_barrier;
    use super::{CELL_LOCK, clear_witness_env, enrol_witness, fresh_dir, witness};
    use ai_memory::store::postgres::PostgresStore;

    /// Scratch database name prefix for this file.
    const SCRATCH_PREFIX: &str = "ai_memory_7241wr";

    /// Spawn-audit caller label for the driven rows.
    const SPAWN_CALLER: &str = "7241-witness";

    /// Fault table: a sequence listed here fails its transaction AT COMMIT.
    const FAIL_TABLE_DDL: &str = "CREATE TABLE public.fail_7241w (seq BIGINT PRIMARY KEY)";

    /// Deferred check that raises at COMMIT for a listed sequence.
    const FAIL_FN_DDL: &str = "CREATE FUNCTION public.fail_7241w_check() RETURNS trigger \
         LANGUAGE plpgsql AS $$ BEGIN \
         IF EXISTS (SELECT 1 FROM public.fail_7241w WHERE seq = NEW.sequence) THEN \
         RAISE EXCEPTION 'issue 7241 forced commit failure'; END IF; RETURN NULL; END $$";

    /// The constraint trigger fires at COMMIT (after the in-tx append returned).
    const FAIL_TRIGGER_DDL: &str = "CREATE CONSTRAINT TRIGGER fail_7241w_at_commit \
         AFTER INSERT ON signed_events DEFERRABLE INITIALLY DEFERRED \
         FOR EACH ROW EXECUTE FUNCTION public.fail_7241w_check()";

    async fn pg_head(pg: &PostgresStore) -> i64 {
        sqlx::query_scalar("SELECT COALESCE(MAX(sequence), 0) FROM signed_events")
            .fetch_one(pg.pool())
            .await
            .expect("read pg head")
    }

    async fn pg_witness_count(pg: &PostgresStore) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM checkpoints WHERE namespace = $1")
            .bind(witness::WITNESS_CHECKPOINT_NAMESPACE)
            .fetch_one(pg.pool())
            .await
            .expect("count pg witness checkpoints")
    }

    async fn append_row(pg: &PostgresStore, n: u64) {
        pg.emit_spawn_audit(&format!("argv0-{n}"), SPAWN_CALLER)
            .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "live postgres: AI_MEMORY_TEST_POSTGRES_URL (postgres-ignored tier)"]
    async fn pg_rolled_back_due_append_burns_the_witness_slot_7241() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let _g = CELL_LOCK.lock().await;
        let scratch = pg_barrier::ScratchDb::create(&url, SCRATCH_PREFIX)
            .await
            .expect("create scratch database");
        let pg = PostgresStore::connect(&scratch.url())
            .await
            .expect("connect scratch database");
        let fdir = fresh_dir("pg-sink");
        let kdir = fresh_dir("pg-keys");
        witness::init(fdir.path(), None).expect("forensic init");
        enrol_witness(kdir.path());
        for ddl in [FAIL_TABLE_DDL, FAIL_FN_DDL, FAIL_TRIGGER_DDL] {
            sqlx::raw_sql(ddl)
                .execute(pg.pool())
                .await
                .expect("install commit-time fault");
        }
        let mut n = 0_u64;
        while !witness::witness_interval_reached(pg_head(&pg).await + 1) {
            n += 1;
            append_row(&pg, n).await;
        }
        let survivor = pg_head(&pg).await;
        let due_sequence = survivor + 1;
        assert_eq!(
            pg_witness_count(&pg).await,
            0,
            "no witness before the due append"
        );

        // The due append's transaction fails AT COMMIT (swallowed by the
        // spawn-audit writer, as in production).
        sqlx::query("INSERT INTO public.fail_7241w (seq) VALUES ($1)")
            .bind(due_sequence)
            .execute(pg.pool())
            .await
            .expect("arm fault");
        append_row(&pg, 0).await;
        sqlx::query("DELETE FROM public.fail_7241w")
            .execute(pg.pool())
            .await
            .expect("disarm fault");
        assert_eq!(
            pg_head(&pg).await,
            survivor,
            "the failed commit discards the row"
        );
        assert_eq!(
            pg_witness_count(&pg).await,
            0,
            "the witness checkpoint row rolls back with the transaction"
        );
        assert!(
            !witness::witness_interval_reached(due_sequence),
            "documented behaviour: the rollback burned the in-transaction witness slot"
        );

        append_row(&pg, 1).await;
        assert_eq!(pg_head(&pg).await, due_sequence);
        while pg_head(&pg).await < due_sequence + witness::WATERMARK_INTERVAL - 1 {
            n += 1;
            append_row(&pg, n).await;
        }
        assert_eq!(
            pg_witness_count(&pg).await,
            0,
            "bounded under-emission: the interval after the burned slot is unwitnessed"
        );
        n += 1;
        append_row(&pg, n).await;
        assert_eq!(
            pg_witness_count(&pg).await,
            1,
            "the witness resumes one WATERMARK_INTERVAL after the burned slot"
        );
        clear_witness_env();
        witness::shutdown();
    }
}
