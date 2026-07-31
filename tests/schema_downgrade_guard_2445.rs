// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::missing_panics_doc
)]
//! v1.0.0 #2445 — the schema DOWNGRADE guard, sqlite arm.
//!
//! # The defect this closes
//!
//! `crate::storage::migrations::migrate` treated "database newer than binary"
//! as "nothing to do" (`if version >= CURRENT_SCHEMA_VERSION { return Ok(()) }`),
//! so an OLDER binary opened a NEWER database silently and then WROTE it —
//! reading columns that moved, ignoring columns it does not know, and violating
//! invariants the newer migrations established. `docs/production-deployment.md`
//! promised a refusal that did not exist, twice, once inside the rollback
//! runbook itself.
//!
//! # What is asserted here (and why each assertion exists)
//!
//! * the guard FIRES on a strictly-newer database, with both versions named;
//! * the guard does NOT fire at `==` or `<` — the normal steady-state and
//!   upgrade paths are byte-identical to pre-#2445 (the R-203 control);
//! * a refused open leaves the database BYTE-IDENTICAL. This is the assertion
//!   that actually proves the gate sits BEFORE `execute_batch(SCHEMA)`. Without
//!   it the change would reduce to a refusal inside `migrate` with the
//!   bootstrap-replay window (the #2424 class) still open, and nothing would
//!   notice;
//! * an UNREADABLE stamp refuses instead of being coerced to `0`. Coercion was
//!   the pre-#2445 `.unwrap_or(0)` behaviour, and because the pre-migration
//!   safety snapshot is gated on `version > 0` it replayed the whole v1 -> tip
//!   ladder over a POPULATED database WITH THE SNAPSHOT SUPPRESSED;
//! * the operator hatch admits ONLY the exact observed version, fails CLOSED on
//!   anything else, and — critically — does NOT replay this binary's bootstrap
//!   DDL over the newer database;
//! * EGRESS survives: `ai-memory backup` still snapshots a schema-ahead
//!   database, because a data-integrity guard whose effect is "you may not back
//!   up your durable text" inverts the directive it serves.

use std::path::Path;

use ai_memory::storage::schema_guard::{ENV_ALLOW_SCHEMA_AHEAD, SchemaStamp, schema_ahead_of};

/// Serialises the process-wide `ENV_ALLOW_SCHEMA_AHEAD` mutations.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn tip() -> i64 {
    ai_memory::storage::migrations::current_schema_version()
}

/// Create a real, fully-migrated database with one row in it, then stamp its
/// recorded schema version to `version`.
fn db_stamped_at(dir: &Path, version: i64) -> std::path::PathBuf {
    let path = dir.join("ai-memory.db");
    {
        let conn = ai_memory::db::open(&path).expect("fresh open must succeed");
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
             confidence, source, metadata, access_count, created_at, updated_at) \
             VALUES ('m-2445', 'long', 'ns', 't', 'durable text', '[]', 5, 1.0, 'api', \
             '{}', 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .expect("seed row");
    }
    let conn = ai_memory::db::open_unmigrated(&path).expect("stamp open");
    conn.execute("DELETE FROM schema_version", []).unwrap();
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        rusqlite::params![version],
    )
    .unwrap();
    path
}

/// Every `sqlite_master` row (name + sql) plus the recorded stamp — the
/// fingerprint a refused open must not move.
fn structure_fingerprint(path: &Path) -> (Vec<(String, Option<String>)>, i64) {
    let conn = ai_memory::db::open_unmigrated(path).expect("fingerprint open");
    let mut stmt = conn
        .prepare("SELECT name, sql FROM sqlite_master ORDER BY name")
        .unwrap();
    let rows: Vec<(String, Option<String>)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    drop(stmt);
    let stamp: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .unwrap();
    (rows, stamp)
}

#[test]
fn guard_refuses_an_open_when_the_database_schema_is_ahead_of_the_binary() {
    let _g = env_lock();
    // SAFETY: process-wide env mutation, serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
    let dir = tempfile::tempdir().unwrap();
    let ahead = tip() + 5;
    let path = db_stamped_at(dir.path(), ahead);

    let err = ai_memory::db::open(&path).expect_err("a newer database must be REFUSED");
    let typed = schema_ahead_of(&err).expect("must be the typed SchemaAheadOfBinary verdict");
    assert_eq!(typed.observed, ahead);
    assert_eq!(typed.supported, tip());
    let msg = err.to_string();
    assert!(msg.contains(&format!("v{ahead}")), "names observed: {msg}");
    assert!(
        msg.contains(&format!("v{}", tip())),
        "names supported: {msg}"
    );
    // The remediation must be actionable, and must not be "give up".
    assert!(
        msg.contains(ENV_ALLOW_SCHEMA_AHEAD),
        "names the hatch: {msg}"
    );
    assert!(
        msg.contains("backup"),
        "names the surviving egress path: {msg}"
    );
}

#[test]
fn a_refused_open_leaves_the_database_byte_identical() {
    // THE assertion that proves L1 fires BEFORE `execute_batch(SCHEMA)`.
    // An older binary's bootstrap DDL replaying over a newer database can
    // resurrect a table or index the newer ladder deliberately removed — the
    // #2424 class — so "refuses" is not enough; it must refuse having touched
    // nothing.
    let _g = env_lock();
    // SAFETY: serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
    let dir = tempfile::tempdir().unwrap();
    let path = db_stamped_at(dir.path(), tip() + 5);

    // Plant a marker object the CURRENT bootstrap does not know about, so a
    // bootstrap replay would be visible as a structural change even if every
    // `CREATE ... IF NOT EXISTS` happened to be a no-op.
    {
        let conn = ai_memory::db::open_unmigrated(&path).unwrap();
        conn.execute_batch("CREATE TABLE future_v92_table (x TEXT)")
            .unwrap();
    }

    let before = structure_fingerprint(&path);
    let _ = ai_memory::db::open(&path).expect_err("refused");
    let after = structure_fingerprint(&path);

    assert_eq!(before, after, "a refused open must not mutate the schema");
    assert!(
        before.0.iter().any(|(n, _)| n == "future_v92_table"),
        "the marker object must survive the refusal"
    );
    let conn = ai_memory::db::open_unmigrated(&path).unwrap();
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok", "refusal must leave the file consistent");
}

#[test]
fn guard_does_not_fire_at_equal_or_older_and_the_normal_path_is_unchanged() {
    // R-203 CONTROL. The steady-state (`==`) and upgrade (`<`) paths must be
    // byte-identical to pre-#2445; only the strictly-greater case is new.
    let _g = env_lock();
    // SAFETY: serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
    let dir = tempfile::tempdir().unwrap();

    // `==` — the fast path.
    let at_tip = db_stamped_at(dir.path(), tip());
    let fp_before = structure_fingerprint(&at_tip);
    ai_memory::db::open(&at_tip).expect("a database AT the tip must open");
    assert_eq!(
        structure_fingerprint(&at_tip),
        fp_before,
        "the `==` fast path must remain a pure no-op"
    );

    // `<` — the ladder still runs and still reaches the tip.
    let dir2 = tempfile::tempdir().unwrap();
    let behind = db_stamped_at(dir2.path(), tip() - 1);
    ai_memory::db::open(&behind).expect("a database BEHIND the tip must migrate forward");
    assert_eq!(structure_fingerprint(&behind).1, tip());

    // A genuinely fresh database is unaffected.
    let dir3 = tempfile::tempdir().unwrap();
    let fresh = dir3.path().join("fresh.db");
    ai_memory::db::open(&fresh).expect("a fresh database must open");
    assert_eq!(structure_fingerprint(&fresh).1, tip());
}

#[test]
fn an_unreadable_stamp_refuses_instead_of_replaying_the_whole_ladder() {
    // Pre-#2445 the read was `.unwrap_or(0)`, and the pre-migration safety
    // snapshot is gated on `version > 0` — so an unreadable stamp replayed
    // v1 -> tip over a POPULATED database with the backup suppressed. That is
    // strictly worse than the defect this issue is named for.
    let _g = env_lock();
    // SAFETY: serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
    let dir = tempfile::tempdir().unwrap();
    let path = db_stamped_at(dir.path(), tip());
    {
        // Make `MAX(version)` undecodable as an integer without dropping the
        // relation — the "present but unreadable" state, distinct from fresh.
        let conn = ai_memory::db::open_unmigrated(&path).unwrap();
        conn.execute_batch(
            "DROP TABLE schema_version; \
             CREATE TABLE schema_version (version TEXT NOT NULL); \
             INSERT INTO schema_version (version) VALUES ('not-an-integer');",
        )
        .unwrap();
    }
    let err = ai_memory::db::open(&path).expect_err("an unreadable stamp must REFUSE");
    assert!(
        err.chain()
            .any(|c| c.to_string().contains("schema version")),
        "the refusal must name the unreadable stamp: {err:#}"
    );
}

#[test]
fn probe_distinguishes_fresh_from_stamped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probe.db");
    {
        // A brand-new file with no relations at all.
        let conn = ai_memory::db::open_unmigrated(&path).unwrap();
        assert_eq!(
            ai_memory::storage::probe_schema_stamp(&conn).unwrap(),
            SchemaStamp::Fresh
        );
    }
    let stamped = db_stamped_at(dir.path(), tip());
    let conn = ai_memory::db::open_unmigrated(&stamped).unwrap();
    assert_eq!(
        ai_memory::storage::probe_schema_stamp(&conn).unwrap(),
        SchemaStamp::Known(tip())
    );
}

#[test]
fn the_exact_version_hatch_admits_and_skips_the_bootstrap_replay() {
    let _g = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let ahead = tip() + 5;
    let path = db_stamped_at(dir.path(), ahead);
    {
        let conn = ai_memory::db::open_unmigrated(&path).unwrap();
        conn.execute_batch("CREATE TABLE future_v92_table (x TEXT)")
            .unwrap();
    }
    // Drop an index the BOOTSTRAP `SCHEMA` const creates. This is what makes
    // the assertion below non-vacuous: if the hatch replayed the bootstrap, the
    // index would come back. Asserting only "the fingerprint did not change"
    // passes even when the bootstrap DOES run, because every statement in it is
    // `IF NOT EXISTS` and therefore a no-op on an already-complete database —
    // i.e. the obvious assertion cannot tell the two implementations apart.
    {
        let conn = ai_memory::db::open_unmigrated(&path).unwrap();
        conn.execute_batch("DROP INDEX IF EXISTS idx_memories_tier")
            .unwrap();
    }
    let before = structure_fingerprint(&path);
    assert!(
        !before.0.iter().any(|(n, _)| n == "idx_memories_tier"),
        "fixture precondition: the bootstrap index must be absent before the open"
    );

    // SAFETY: serialised by `_g`.
    unsafe { std::env::set_var(ENV_ALLOW_SCHEMA_AHEAD, ahead.to_string()) };
    let conn = ai_memory::db::open(&path).expect("the exact-version hatch must admit");
    // The durable text is reachable through the hatched connection.
    let title: String = conn
        .query_row("SELECT title FROM memories WHERE id = 'm-2445'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(title, "t");
    drop(conn);
    // SAFETY: serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };

    let after = structure_fingerprint(&path);
    assert!(
        !after.0.iter().any(|(n, _)| n == "idx_memories_tier"),
        "the hatch must NOT replay this binary's bootstrap DDL over a newer \
         database — the dropped bootstrap index came back, so `execute_batch(SCHEMA)` ran"
    );
    assert_eq!(
        after, before,
        "the hatch must leave the database EXACTLY as found — no bootstrap, no \
         ladder, no trigger install"
    );
}

#[test]
fn the_hatch_fails_closed_on_anything_but_the_exact_observed_version() {
    let _g = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let ahead = tip() + 5;
    let path = db_stamped_at(dir.path(), ahead);

    for bad in ["1", "true", "yes", "on", "", "   ", "abc", "-5"] {
        // SAFETY: serialised by `_g`.
        unsafe { std::env::set_var(ENV_ALLOW_SCHEMA_AHEAD, bad) };
        assert!(
            ai_memory::db::open(&path).is_err(),
            "hatch value {bad:?} must fail CLOSED"
        );
    }
    // A DIFFERENT version does not authorise this database, and says so.
    // SAFETY: serialised by `_g`.
    unsafe { std::env::set_var(ENV_ALLOW_SCHEMA_AHEAD, (ahead - 1).to_string()) };
    let err = ai_memory::db::open(&path).expect_err("a mismatched hatch must refuse");
    assert!(
        err.to_string().contains("does not authorise"),
        "a stale unit file must be diagnosable: {err}"
    );
    // SAFETY: serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
}

#[test]
fn egress_survives_the_refusal_the_unmigrated_funnel_still_reads_the_durable_text() {
    // The North Star reading: the memory TEXT is the source of truth and the
    // schema shape is a derived property of it, so a guard whose observable
    // effect is "you may not read or back up your own corpus" inverts the very
    // directive it serves. `open_unmigrated` is the funnel `ai-memory backup`
    // falls back to; `open_read_only` cannot serve it because
    // `PRAGMA query_only = ON` refuses `VACUUM INTO`.
    let _g = env_lock();
    // SAFETY: serialised by `_g`.
    unsafe { std::env::remove_var(ENV_ALLOW_SCHEMA_AHEAD) };
    let dir = tempfile::tempdir().unwrap();
    let path = db_stamped_at(dir.path(), tip() + 5);
    assert!(ai_memory::db::open(&path).is_err(), "writer open refuses");

    let conn = ai_memory::db::open_unmigrated(&path).expect("egress funnel must still open");
    let content: String = conn
        .query_row(
            "SELECT content FROM memories WHERE id = 'm-2445'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(content, "durable text");

    // And the snapshot itself works — the operation `backup` actually performs.
    let snapshot = dir.path().join("snapshot.db");
    conn.execute(&format!("VACUUM INTO '{}'", snapshot.display()), [])
        .expect("VACUUM INTO must succeed through the unmigrated funnel");
    assert!(snapshot.exists(), "the snapshot must land on disk");
}
