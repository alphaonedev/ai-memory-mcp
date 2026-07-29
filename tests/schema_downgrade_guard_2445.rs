// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2445 — R-203 regression suite for the open-time schema
//! DOWNGRADE guard.
//!
//! **What was broken.** Both migrate entrypoints treated "database newer
//! than binary" as "nothing to do":
//!
//! ```ignore
//! if version >= CURRENT_SCHEMA_VERSION { return Ok(()); }
//! ```
//!
//! so an OLDER binary opening a NEWER database proceeded to read and
//! WRITE it — schema-level corruption with no warning, on the deployment
//! least able to notice (a partial canary rollback). Meanwhile
//! `docs/production-deployment.md` promised a downgrade refusal twice,
//! once inside the rollback runbook itself.
//!
//! **R-203 direction check.** Every test in this file FAILS on the parent
//! commit and PASSES after:
//!
//! - [`older_binary_refuses_to_open_a_newer_database`] — on the parent,
//!   `db::open` returns `Ok`, so the `expect_err` fails.
//! - [`older_binary_must_not_write_into_a_newer_database`] — the
//!   "and WRITES it" half. On the parent the open succeeds AND the
//!   subsequent `db::insert` lands, and the test panics with that write
//!   as the evidence.
//! - [`refusal_runs_before_any_ddl_touches_the_newer_database`] — on the
//!   parent, `execute_batch(SCHEMA)` + the CHECK-trigger installer run
//!   against the newer database before anything refuses, so the
//!   `sqlite_master` fingerprint moves.
//!
//! **Postgres.** The guard is symmetric (`connect` probes before
//! `INIT_SCHEMA`; `migrate_locked` re-checks before the ladder) and both
//! arms delegate the decision + the operator-facing text to the same
//! backend-neutral SSOT in `crate::storage::migrations`, so an operator
//! reads an identical remedy on either backend. Postgres coverage is two
//! layers: the `#[ignore]`d live-postgres end-to-end below (run in the
//! live-PG SAL lane via `--include-ignored`), plus the ALWAYS-COMPILED,
//! ALWAYS-RUN source-text parity guard
//! `guardrail_2445_postgres_lanes_reference_the_downgrade_guard` in
//! `tests/migration_ladder_integrity.rs` — so a future edit that drops
//! the guard from either postgres lane reds a normal CI run, with no
//! live postgres required.

use ai_memory::storage::migrations::{ALLOW_SCHEMA_DOWNGRADE_ENV, current_schema_version};
use rusqlite::Connection;
use std::path::Path;

/// Serializes the one env-mutating test in this file. `std::env::set_var`
/// is unsound under concurrent access, and every `tests/*.rs` file is its
/// own test binary, so a file-local guard is a genuine process-wide
/// critical section here. (The crate-canonical `config::test_env_lock`
/// is `pub(crate)` and unreachable from an integration-test crate; this
/// file is the only place in the process that touches
/// `AI_MEMORY_ALLOW_SCHEMA_DOWNGRADE`.)
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Clears the hatch env on drop so a panicking test cannot leak a
/// downgrade sanction into whatever runs next in this binary.
struct ClearHatchOnDrop;
impl Drop for ClearHatchOnDrop {
    fn drop(&mut self) {
        unsafe { std::env::remove_var(ALLOW_SCHEMA_DOWNGRADE_ENV) };
    }
}

/// Take the process-wide env critical section and guarantee the hatch is
/// UNSET for the duration.
///
/// EVERY test in this file needs this, not just the one that sets the
/// variable: `AI_MEMORY_ALLOW_SCHEMA_DOWNGRADE` is process-global, so a
/// concurrent test holding a sanction for version N would silently
/// license the refusal tests that happen to probe version N. (That is
/// not hypothetical — it is exactly what happened on the first run of
/// this suite.)
///
/// Callers bind BOTH returns as separate `let` bindings, lock FIRST:
/// drop order is reverse of declaration, so the clear-guard runs before
/// the lock is released and the variable is never observable to the next
/// test.
fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    let guard = ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    unsafe { std::env::remove_var(ALLOW_SCHEMA_DOWNGRADE_ENV) };
    guard
}

/// A minimal, valid `Memory` for the write-path probes. Deliberately a
/// real `db::insert` subject (not a raw SQL INSERT) so the "and WRITES
/// it" half of #2445 is proven through the substrate's own write funnel.
fn probe_memory(id: &str, title: &str) -> ai_memory::models::Memory {
    let now = chrono::Utc::now().to_rfc3339();
    ai_memory::models::Memory {
        id: id.to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: "downgrade-guard-2445".to_string(),
        title: title.to_string(),
        content: "the memory TEXT is the durable source of truth".to_string(),
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        ..ai_memory::models::Memory::default()
    }
}

/// Everything an older binary must leave BYTE-IDENTICAL when it refuses a
/// newer database: the full DDL surface, the row census, and the version
/// stamp itself (a refusal is not licence to renumber someone else's
/// schema).
#[derive(Debug, PartialEq, Eq)]
struct DbFingerprint {
    /// Every `sqlite_master` row's `type|name|sql`, sorted — moves if any
    /// CREATE TABLE / INDEX / TRIGGER fires.
    ddl: Vec<String>,
    memories: i64,
    schema_version: i64,
}

/// Fingerprint via a RAW rusqlite connection — never `db::open`, which is
/// the very funnel under test.
fn fingerprint(path: &Path) -> DbFingerprint {
    let conn = Connection::open(path).expect("raw open for fingerprint");
    let mut stmt = conn
        .prepare("SELECT type, name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name")
        .expect("prepare sqlite_master scan");
    let mut ddl: Vec<String> = stmt
        .query_map([], |r| {
            Ok(format!(
                "{}|{}|{}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?
            ))
        })
        .expect("scan sqlite_master")
        .map(|r| r.expect("sqlite_master row"))
        .collect();
    ddl.sort();
    let memories: i64 = conn
        .query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))
        .expect("count memories");
    let schema_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .expect("read schema_version");
    DbFingerprint {
        ddl,
        memories,
        schema_version,
    }
}

/// Build a real, migrated, populated database and then stamp its
/// `schema_version` ABOVE this binary's ladder tip — exactly the on-disk
/// state a newer binary leaves behind after it migrates, which the
/// operator then points an older binary at during a partial rollback.
///
/// Stamped with a RAW connection so the ladder does not immediately
/// ratchet the value back down.
fn newer_database(dir: &Path, bump: i64) -> std::path::PathBuf {
    let db_path = dir.join("ai-memory.db");
    {
        let conn = ai_memory::db::open(&db_path).expect("open + migrate a fresh database");
        let mem = probe_memory("seed-2445", "durable truth");
        ai_memory::db::insert(&conn, &mem).expect("seed a row so loss would be observable");
    }
    let raw = Connection::open(&db_path).expect("raw open to stamp a newer version");
    raw.execute("DELETE FROM schema_version", [])
        .expect("clear stamp");
    raw.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        rusqlite::params![current_schema_version() + bump],
    )
    .expect("stamp a newer schema version");
    drop(raw);
    db_path
}

/// R-203 core: the open is REFUSED.
///
/// On the parent commit `db::open` returns `Ok(conn)` — the migrate
/// entrypoint's `version >= CURRENT_SCHEMA_VERSION` fast path treats the
/// newer database as "nothing to do" — and this `expect_err` fails.
#[test]
fn older_binary_refuses_to_open_a_newer_database() {
    let _lock = lock_env();
    let _clear = ClearHatchOnDrop;
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = newer_database(tmp.path(), 1);

    let err = ai_memory::db::open(&db_path)
        .expect_err("#2445: an older binary must REFUSE a newer database, not open it");
    let msg = format!("{err:#}");

    assert!(
        msg.contains("NEWER than this binary supports"),
        "refusal must name the downgrade condition: {msg}"
    );
    assert!(
        msg.contains(&format!("v{}", current_schema_version() + 1)),
        "refusal must report the OBSERVED on-disk version: {msg}"
    );
    assert!(
        msg.contains(&format!("v{}", current_schema_version())),
        "refusal must report the version this binary EXPECTS: {msg}"
    );
    // A guard with no documented remedy is a support burden — and this one
    // fires mid-rollback. The refusal must carry the way out.
    assert!(
        msg.contains(ALLOW_SCHEMA_DOWNGRADE_ENV),
        "refusal must name the escape hatch: {msg}"
    );
    assert!(
        msg.contains("re-install") && msg.contains("snapshot"),
        "refusal must name the recovery ladder (reinstall / restore snapshot): {msg}"
    );
}

/// R-203, the "and WRITES it" half — the part that makes #2445 a
/// data-integrity defect rather than a cosmetic one.
///
/// On the parent commit the open succeeds AND the insert lands, and this
/// test panics naming the write it just performed against a schema the
/// binary does not understand.
#[test]
fn older_binary_must_not_write_into_a_newer_database() {
    let _lock = lock_env();
    let _clear = ClearHatchOnDrop;
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = newer_database(tmp.path(), 3);
    let observed = current_schema_version() + 3;

    match ai_memory::db::open(&db_path) {
        Err(_) => { /* guarded: no connection is ever handed out. */ }
        Ok(conn) => {
            let mem = probe_memory(
                "too-old-write-2445",
                "written by a binary too old for this schema",
            );
            let wrote = ai_memory::db::insert(&conn, &mem);
            panic!(
                "#2445: a binary whose ladder tips at v{} OPENED a v{observed} database and the \
                 write returned {wrote:?} — an older binary is mutating a schema it does not \
                 understand, silently, with no warning.",
                current_schema_version()
            );
        }
    }
}

/// The refusal must land BEFORE any DDL touches the newer database.
///
/// `db::open` replays this binary's entire bootstrap `SCHEMA` on every
/// open. Its statements are `IF NOT EXISTS`, but that keys on the object
/// NAME, so an older binary would still author DDL for objects a later
/// version reshaped. On the parent commit the bootstrap batch AND the
/// CHECK-trigger installer both run against the newer database before
/// anything refuses, so the fingerprint moves and this test fails.
#[test]
fn refusal_runs_before_any_ddl_touches_the_newer_database() {
    let _lock = lock_env();
    let _clear = ClearHatchOnDrop;
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = newer_database(tmp.path(), 2);

    let before = fingerprint(&db_path);
    let _ = ai_memory::db::open(&db_path);
    let after = fingerprint(&db_path);

    assert_eq!(
        before, after,
        "#2445: a refused open must leave the newer database byte-identical — no bootstrap DDL, \
         no trigger install, and above all no rewrite of someone else's schema_version stamp"
    );
    assert_eq!(
        after.schema_version,
        current_schema_version() + 2,
        "the newer version stamp must survive the refusal untouched"
    );
    assert_eq!(after.memories, 1, "the seeded row must survive the refusal");
}

/// A database at EXACTLY the binary's tip is the normal steady state and
/// must keep opening. This is the guard's blast-radius floor: the fix
/// refuses only a STRICTLY newer stamp.
#[test]
fn same_version_database_still_opens() {
    let _lock = lock_env();
    let _clear = ClearHatchOnDrop;
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("ai-memory.db");
    drop(ai_memory::db::open(&db_path).expect("fresh open"));
    // Second open crosses the guard with on_disk == tip.
    let conn = ai_memory::db::open(&db_path).expect("re-open at the current tip must succeed");
    let v: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .expect("read stamp");
    assert_eq!(v, current_schema_version());
}

/// The escape hatch is version-EXACT, not boolean — end to end through
/// the real `db::open` funnel.
///
/// A boolean sanction baked into a systemd unit or container image for
/// one rollback would silently blanket-permit an arbitrarily larger gap
/// at the next schema bump, across a whole fleet. Pinning the value to
/// the observed version makes each sanction single-shot and
/// self-expiring.
#[test]
fn hatch_is_version_exact_and_self_expiring() {
    let _lock = lock_env();
    let _clear = ClearHatchOnDrop;

    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = newer_database(tmp.path(), 1);
    let observed = current_schema_version() + 1;

    // A boolean does NOT open the guard.
    unsafe { std::env::set_var(ALLOW_SCHEMA_DOWNGRADE_ENV, "1") };
    assert!(
        ai_memory::db::open(&db_path).is_err(),
        "a boolean hatch value must not sanction a downgrade"
    );

    // A STALE sanction (naming a different version) does NOT open it.
    unsafe {
        std::env::set_var(
            ALLOW_SCHEMA_DOWNGRADE_ENV,
            current_schema_version().to_string(),
        );
    }
    assert!(
        ai_memory::db::open(&db_path).is_err(),
        "a sanction pinned to a different version must not carry over"
    );

    // The EXACT observed version opens it — and the operator gets a real,
    // working connection (the hatch must not be a decorative no-op).
    unsafe { std::env::set_var(ALLOW_SCHEMA_DOWNGRADE_ENV, observed.to_string()) };
    let conn =
        ai_memory::db::open(&db_path).expect("exact-version sanction must open the database");
    let v: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .expect("read stamp");
    assert_eq!(
        v, observed,
        "a sanctioned open must NOT rewrite the newer version stamp down to this binary's tip"
    );
}

/// Live-postgres end-to-end twin. `#[ignore]` + `sal-postgres`, run in the
/// live-PG SAL lane via `--include-ignored`; self-skips when
/// `AI_MEMORY_TEST_POSTGRES_URL` is unset.
///
/// The always-compiled CI-visible parity guard for the same two postgres
/// lanes is
/// `guardrail_2445_postgres_lanes_reference_the_downgrade_guard` in
/// `tests/migration_ladder_integrity.rs`.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
#[ignore = "requires a live postgres via AI_MEMORY_TEST_POSTGRES_URL"]
async fn postgres_refuses_to_connect_to_a_newer_database() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skipping: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };

    // Bring the schema to this binary's tip, then stamp it ABOVE the tip
    // out-of-band — the state a newer binary leaves behind.
    let store = ai_memory::store::postgres::PostgresStore::connect(&url)
        .await
        .expect("baseline connect must succeed");
    drop(store);

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("raw pool for stamping");
    let observed = i32::try_from(current_schema_version()).expect("tip fits i32") + 1;
    sqlx::query("DELETE FROM schema_version")
        .execute(&pool)
        .await
        .expect("clear stamp");
    sqlx::query("INSERT INTO schema_version (version) VALUES ($1)")
        .bind(observed)
        .execute(&pool)
        .await
        .expect("stamp a newer schema version");

    let refused = ai_memory::store::postgres::PostgresStore::connect(&url).await;
    let err = match refused {
        Err(e) => format!("{e}"),
        Ok(_) => {
            // Restore before failing so the shared test database is not
            // left stamped high for every subsequent test.
            restore_pg_stamp(&pool).await;
            panic!(
                "#2445 [postgres]: connect() accepted a v{observed} database against a v{} binary",
                current_schema_version()
            );
        }
    };

    restore_pg_stamp(&pool).await;

    assert!(
        err.contains("NEWER than this binary supports"),
        "postgres refusal must carry the shared SSOT text: {err}"
    );
    assert!(
        err.contains(ALLOW_SCHEMA_DOWNGRADE_ENV),
        "postgres refusal must name the same escape hatch as sqlite: {err}"
    );
}

/// Put the shared `ai_memory_test` database's stamp back at this binary's
/// tip. The postgres test database is shared across the whole SAL suite —
/// leaving it stamped high would refuse every subsequent connect.
#[cfg(feature = "sal-postgres")]
async fn restore_pg_stamp(pool: &sqlx::PgPool) {
    let tip = i32::try_from(current_schema_version()).expect("tip fits i32");
    sqlx::query("DELETE FROM schema_version")
        .execute(pool)
        .await
        .expect("clear stamp for restore");
    sqlx::query("INSERT INTO schema_version (version) VALUES ($1)")
        .bind(tip)
        .execute(pool)
        .await
        .expect("restore stamp to this binary's tip");
}
