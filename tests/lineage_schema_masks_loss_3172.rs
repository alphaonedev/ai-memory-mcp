// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 (#3172) — regression: `agent_lineage` SCHEMA-masks-DATA-LOSS gate.
//!
//! `agent_lineage` ships in the bootstrap `SCHEMA` const, which `db::open`
//! replays on EVERY open BEFORE the migration ladder. A dropped/emptied table
//! was silently re-created EMPTY, the v80 rebuild "succeeded" over zero rows,
//! and the whole identity-lineage chain vanished with no skip logged —
//! undetectable by the #3113 table-existence probe. The fix persists a
//! high-water mark and FAILS CLOSED when the append-only relation regresses
//! below it.
//!
//! These are FULL-FUNNEL tests: they drive the real `db::open` (sqlite) and
//! `PostgresStore::connect` (postgres, gated on `AI_MEMORY_TEST_POSTGRES_URL`)
//! paths, seeding lineage rows, recording the mark, then emptying the relation
//! and asserting the open refuses — and that the operator override proceeds.

// The postgres test serializes on a process-global env `Mutex` across `.await`
// points (the override env var is process-wide); this is the established
// convention for env-serialized live-PG tests (see `cov_postgres_lineage.rs`).
#![allow(clippy::await_holding_lock)]

use std::sync::Mutex;

use rusqlite::Connection;

/// The override env var is process-global; serialize the tests that toggle it.
static ENV_LOCK: Mutex<()> = Mutex::new(());

const OVERRIDE_ENV: &str = "AI_MEMORY_ALLOW_LINEAGE_REGRESSION";

/// Insert `n` distinct-epoch `agent_lineage` succession rows (all NOT NULL
/// columns satisfied; `reason` within the CHECK set).
fn seed_lineage(conn: &Connection, n: i64) {
    for epoch in 0..n {
        conn.execute(
            "INSERT INTO agent_lineage \
             (agent_id, epoch, reason, predecessor_pubkey, successor_pubkey, not_before, \
              prev_record_hash, signature, record_bytes, created_at) \
             VALUES ('ai:lineage-3172', ?1, 'genesis', 'pk_pred', 'pk_succ', \
              '2026-01-01T00:00:00Z', X'00', X'00', X'00', '2026-01-01T00:00:00Z')",
            [epoch],
        )
        .expect("seed agent_lineage row");
    }
}

#[test]
fn sqlite_open_refuses_when_agent_lineage_regressed_to_empty() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Ensure no stale override leaks in from another test / the environment.
    unsafe { std::env::remove_var(OVERRIDE_ENV) };

    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let path = f.path();

    // Open #1: fresh schema, agent_lineage empty, no mark recorded.
    {
        let conn = ai_memory::db::open(path).expect("open #1 (fresh)");
        seed_lineage(&conn, 4);
    }
    // Open #2: migrate observes 4 rows and records the high-water mark = 4.
    {
        let _conn = ai_memory::db::open(path).expect("open #2 (records mark)");
    }
    // Simulate the schema-masked loss: empty the append-only relation. (A real
    // DROP would be re-created empty by the SCHEMA replay to the same effect.)
    {
        let conn = ai_memory::db::open(path).expect("open #3 (still intact)");
        conn.execute("DELETE FROM agent_lineage", [])
            .expect("empty the lineage relation");
    }
    // Open #4: the mark (4) now exceeds the live count (0) — FAIL CLOSED.
    let err = ai_memory::db::open(path).expect_err("open #4 MUST refuse the emptied lineage");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("agent_lineage"),
        "message must name the relation: {msg}"
    );
    assert!(
        msg.contains("UNCHANGED"),
        "message must state the DB is unchanged: {msg}"
    );
    assert!(
        msg.contains(OVERRIDE_ENV),
        "message must name the override knob: {msg}"
    );

    // The refusal is not a mutation: the database is still readable and the
    // stamp/mark are untouched (a fresh open with the override then proceeds).
    unsafe { std::env::set_var(OVERRIDE_ENV, "1") };
    {
        let conn = ai_memory::db::open(path).expect("override acknowledges the loss and proceeds");
        // The mark has been reset to the current (0) count.
        let mark: Option<i64> = conn
            .query_row(
                "SELECT high_water FROM lineage_integrity_watermark WHERE relation = 'agent_lineage'",
                [],
                |r| r.get(0),
            )
            .ok();
        assert_eq!(
            mark,
            Some(0),
            "override must RESET the mark to the current count"
        );
    }
    unsafe { std::env::remove_var(OVERRIDE_ENV) };

    // After the reset, a clean re-open succeeds (baseline is now 0).
    let _conn = ai_memory::db::open(path).expect("post-reset open is clean");
}

#[test]
fn sqlite_fresh_and_upgrade_databases_are_never_bricked() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    unsafe { std::env::remove_var(OVERRIDE_ENV) };

    // A genuinely fresh DB (empty agent_lineage, no mark) must open cleanly
    // every time — the anti-brick invariant. Re-opening repeatedly must never
    // start refusing.
    let f = tempfile::NamedTempFile::new().expect("tempfile");
    let path = f.path();
    for _ in 0..3 {
        let _conn = ai_memory::db::open(path).expect("fresh empty DB always opens");
    }
}

// ---------------------------------------------------------------------------
// Postgres twin — gated on AI_MEMORY_TEST_POSTGRES_URL, skips cleanly when unset.
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
fn postgres_url() -> Option<String> {
    std::env::var("AI_MEMORY_TEST_POSTGRES_URL").ok()
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn postgres_connect_refuses_when_agent_lineage_regressed() {
    use ai_memory::store::postgres::PostgresStore;

    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(url) = postgres_url() else {
        eprintln!("AI_MEMORY_TEST_POSTGRES_URL unset — skipping postgres #3172 regression");
        return;
    };
    unsafe { std::env::remove_var(OVERRIDE_ENV) };

    // Isolate this test's schema so it cannot collide with a shared corpus.
    let schema = format!(
        "lineage_3172_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    );
    let raw = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .expect("raw pool");
    sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS {schema}"))
        .execute(&raw)
        .await
        .expect("create isolated schema");
    // Route this test's connect at the isolated schema, keeping `public` on the
    // path so the `vector` extension type (installed in public) still resolves
    // while unqualified `CREATE TABLE` lands in the isolated schema first. A
    // caller-pinned search_path is returned unchanged by the adapter's
    // normalization (the #1381 test-isolation contract).
    let scoped_url = if url.contains('?') {
        format!("{url}&options=-c%20search_path%3D{schema}%2Cpublic")
    } else {
        format!("{url}?options=-c%20search_path%3D{schema}%2Cpublic")
    };

    // Connect #1: fresh isolated schema, seed 3 lineage rows.
    {
        let _store = PostgresStore::connect(&scoped_url)
            .await
            .expect("pg connect #1 (fresh)");
        sqlx::query(&format!(
            "INSERT INTO {schema}.agent_lineage \
             (agent_id, epoch, reason, predecessor_pubkey, successor_pubkey, not_before, \
              prev_record_hash, signature, record_bytes, created_at) \
             SELECT 'ai:lineage-3172', g, 'genesis', 'pk_pred', 'pk_succ', \
              '2026-01-01T00:00:00Z', '\\x00', '\\x00', '\\x00', '2026-01-01T00:00:00Z' \
             FROM generate_series(0, 2) AS g"
        ))
        .execute(&raw)
        .await
        .expect("seed pg lineage rows");
    }
    // Connect #2: records the mark = 3.
    {
        let _store = PostgresStore::connect(&scoped_url)
            .await
            .expect("pg connect #2 (records mark)");
    }
    // Simulate the schema-masked loss.
    sqlx::query(&format!("DELETE FROM {schema}.agent_lineage"))
        .execute(&raw)
        .await
        .expect("empty pg lineage relation");

    // Connect #3: mark (3) exceeds live (0) — FAIL CLOSED. (`PostgresStore` is
    // not `Debug`, so match rather than `expect_err`.)
    let Err(err) = PostgresStore::connect(&scoped_url).await else {
        // Best-effort cleanup before failing.
        let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
            .execute(&raw)
            .await;
        panic!("pg connect #3 MUST refuse the emptied lineage");
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("agent_lineage"),
        "pg message must name the relation: {msg}"
    );
    assert!(
        msg.contains(OVERRIDE_ENV),
        "pg message must name the override knob: {msg}"
    );

    // Override acknowledges the loss, resets the mark, and proceeds.
    unsafe { std::env::set_var(OVERRIDE_ENV, "1") };
    {
        let _store = PostgresStore::connect(&scoped_url)
            .await
            .expect("pg override proceeds");
        let mark: Option<i64> = sqlx::query_scalar(&format!(
            "SELECT high_water FROM {schema}.lineage_integrity_watermark WHERE relation = 'agent_lineage'"
        ))
        .fetch_optional(&raw)
        .await
        .expect("read pg mark");
        assert_eq!(mark, Some(0), "pg override must RESET the mark");
    }
    unsafe { std::env::remove_var(OVERRIDE_ENV) };

    // Cleanup the isolated schema.
    let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
        .execute(&raw)
        .await;
}
