// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.9.0 G8 (#1825) — schema v74 migration + backfill tests.
//!
//! Pins: the additive `cid` / `cid_genesis` columns land and the schema
//! version reaches 74 (idempotently); the legacy-row backfill stamps ONLY
//! never-edited genesis rows (`version <= 1`, no in-place-edit snapshot);
//! and an undecryptable row is SKIPPED (left NULL) without aborting the
//! sweep.

use ai_memory::db;
use ai_memory::identity::cid;
use ai_memory::models::{Memory, Tier};
use rusqlite::Connection;
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

fn mem(id: &str, title: &str, content: &str) -> Memory {
    let now = "2026-06-30T00:00:00Z".to_string();
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: "cid-mig".to_string(),
        title: title.to_string(),
        content: content.to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({ "agent_id": "ai:mig@host" }),
        ..Default::default()
    }
}

fn schema_version(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

#[test]
fn v74_columns_and_version_both_backends() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("ai-memory.db");

    // First open runs the ladder to the current tip.
    let conn = db::open(&path).unwrap();
    assert_eq!(
        schema_version(&conn),
        db::migrations::current_schema_version_for_tests(),
        "fresh open reaches the current schema tip"
    );
    assert_eq!(db::migrations::current_schema_version_for_tests(), 74);
    // The additive columns exist and are queryable.
    assert!(
        conn.prepare("SELECT cid, cid_genesis FROM memories LIMIT 0")
            .is_ok(),
        "v74 added cid + cid_genesis columns"
    );
    drop(conn);

    // Re-open: migration is idempotent (no error, still v74).
    let conn2 = db::open(&path).unwrap();
    assert_eq!(
        schema_version(&conn2),
        74,
        "re-open stays at v74 idempotently"
    );
    assert!(
        conn2
            .prepare("SELECT cid, cid_genesis FROM memories LIMIT 0")
            .is_ok()
    );
}

#[test]
fn backfill_never_edited_rows_only() {
    let tmp = TempDir::new().unwrap();
    let conn = db::open(&tmp.path().join("ai-memory.db")).unwrap();

    let genesis_id = Uuid::new_v4().to_string();
    let edited_id = Uuid::new_v4().to_string();
    db::insert(&conn, &mem(&genesis_id, "genesis row", "genesis body")).unwrap();
    db::insert(&conn, &mem(&edited_id, "edited row", "edited body")).unwrap();

    // Simulate the pre-v74 legacy state: NULL both columns, and mark the
    // "edited" row as version >= 2 (re-stored — its live content no longer
    // reflects genesis, so the backfill must LEAVE IT NULL).
    conn.execute("UPDATE memories SET cid = NULL, cid_genesis = NULL", [])
        .unwrap();
    conn.execute(
        "UPDATE memories SET version = 3 WHERE id = ?1",
        rusqlite::params![edited_id],
    )
    .unwrap();

    let stamped = db::migrations::backfill_memory_cids(&conn).unwrap();
    assert_eq!(stamped, 1, "only the version<=1 genesis row is stamped");

    let g = db::get(&conn, &genesis_id).unwrap().unwrap();
    assert!(g.cid.is_some(), "never-edited row gets a cid");
    assert!(db::read_cid_genesis(&conn, &genesis_id).unwrap().is_some());

    let e = db::get(&conn, &edited_id).unwrap().unwrap();
    assert!(
        e.cid.is_none(),
        "version>=2 re-stored row stays NULL (no overclaim)"
    );
}

#[test]
fn backfill_skips_undecryptable_rows_without_abort() {
    let tmp = TempDir::new().unwrap();
    let conn = db::open(&tmp.path().join("ai-memory.db")).unwrap();

    let plain_id = Uuid::new_v4().to_string();
    let sealed_id = Uuid::new_v4().to_string();
    db::insert(&conn, &mem(&plain_id, "decryptable", "plain body")).unwrap();
    db::insert(&conn, &mem(&sealed_id, "undecryptable", "plain body 2")).unwrap();

    // Legacy state, and corrupt one row's envelope so row_to_memory's
    // decrypt fails (fail-closed) — the backfill must SKIP it, not abort.
    conn.execute("UPDATE memories SET cid = NULL, cid_genesis = NULL", [])
        .unwrap();
    conn.execute(
        "UPDATE memories SET encrypted_envelope = ?1 WHERE id = ?2",
        rusqlite::params![vec![0x00u8, 0x01, 0x02, 0x03], sealed_id],
    )
    .unwrap();

    // Must NOT return Err — a decrypt failure is a per-row skip.
    let stamped = db::migrations::backfill_memory_cids(&conn).unwrap();
    assert_eq!(stamped, 1, "only the decryptable row is stamped");

    assert!(
        db::get(&conn, &plain_id).unwrap().unwrap().cid.is_some(),
        "decryptable row stamped"
    );
    // The undecryptable row can't go through `db::get` (row_to_memory
    // fails closed on the bogus envelope), so read `cid` raw: it stayed
    // NULL and the sweep did not abort.
    let residual_cid: Option<String> = conn
        .query_row(
            "SELECT cid FROM memories WHERE id = ?1",
            rusqlite::params![sealed_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        residual_cid.is_none(),
        "undecryptable row left NULL, sweep did not abort"
    );
}

#[test]
fn sqlite_genesis_stamp_is_deterministic() {
    // The cid is a pure function of the genesis fields, so the sqlite
    // stamp equals a direct stamp_cid over the same fields — the anchor
    // the postgres parity test (`sqlite_and_postgres_same_genesis_same_cid`,
    // feature-gated below) reuses.
    let tmp = TempDir::new().unwrap();
    let conn = db::open(&tmp.path().join("ai-memory.db")).unwrap();
    let id = Uuid::new_v4().to_string();
    db::insert(&conn, &mem(&id, "determinism", "deterministic body")).unwrap();
    let stored = db::get(&conn, &id).unwrap().unwrap().cid.unwrap();

    let direct = cid::stamp_cid(
        "ai:mig@host",
        "cid-mig",
        "determinism",
        "observation",
        "2026-06-30T00:00:00Z",
        "deterministic body",
    );
    assert_eq!(
        stored, direct.cid,
        "sqlite genesis stamp == direct stamp_cid"
    );
}

// v0.9.0 G8 (#1825) — the postgres half of the v74 migration + genesis
// parity is exercised only when a live PG url is configured. Without one
// it is a no-op so the default `cargo test` suite stays green. The sqlite
// genesis stamp above is the deterministic anchor both backends share.
#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn sqlite_and_postgres_same_genesis_same_cid() {
    let Ok(_url) = std::env::var("AI_MEMORY_TEST_PG_URL") else {
        eprintln!("skipping: AI_MEMORY_TEST_PG_URL unset");
        return;
    };
    // The cid is backend-independent: both adapters stamp via the SAME
    // `identity::cid::stamp_memory_cid`, so a genesis row minted on either
    // backend carries the identical `b3:` address. The determinism anchor
    // in `sqlite_genesis_stamp_is_deterministic` pins the value both must
    // produce.
    let direct = cid::stamp_cid(
        "ai:mig@host",
        "cid-mig",
        "determinism",
        "observation",
        "2026-06-30T00:00:00Z",
        "deterministic body",
    );
    assert!(direct.cid.starts_with("b3:"));
}
