// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #10157 — the keyless refusal inside `migrate_inner` itself, with no
//! `db::open` provisioning in front of it. `db::open` resolves the signer
//! before it reaches the ladder, so a test through `db::open` cannot tell a
//! ladder that refuses from one that falls back to a scratch key. This test
//! drives the ladder directly with a signer source that fails.

use super::{SCHEMA, migrate_inner, migrate_signed};
use crate::governance::daemon_signer::{DaemonChainSigner, DaemonKeyCause, DaemonKeyMissing};
use crate::signed_events::agent_cutover::AGENT_CUTOVER_EVENT_TYPE;
use rusqlite::{Connection, params};
use std::path::{Path, PathBuf};

/// The rung below the v103 cut-over (#10108).
const V102_RUNG: i64 = 102;
/// In-tree scratch root (project no-`/tmp` rule).
const SCRATCH_SUBDIR: &str = "migrations-keyless-10157";

fn scratch_root() -> PathBuf {
    let root = std::env::current_dir()
        .expect("cwd")
        .join(".local-runs")
        .join(SCRATCH_SUBDIR);
    std::fs::create_dir_all(&root).expect("scratch root");
    root
}

/// Every file in `dir` with its bytes, sorted by name.
fn dir_bytes(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .expect("read dir")
        .map(|e| {
            let e = e.expect("dir entry");
            let name = e.file_name().to_string_lossy().into_owned();
            let bytes = std::fs::read(e.path()).expect("read file");
            (name, bytes)
        })
        .collect();
    out.sort();
    out
}

fn version(conn: &Connection) -> i64 {
    conn.query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .expect("schema_version")
}

fn markers(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
        params![AGENT_CUTOVER_EVENT_TYPE],
        |r| r.get(0),
    )
    .expect("marker count")
}

/// A v102 database file holding one durable row: built to the tip with a
/// scratch signer, then rewound (marker removed, stamp back to 102).
fn make_v102(db: &Path, key_dir: &Path) {
    let signer = DaemonChainSigner::provision(key_dir).expect("scratch signer");
    let conn = Connection::open(db).expect("open file db");
    conn.execute_batch(SCHEMA).expect("apply SCHEMA");
    conn.execute_batch(
        "DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES (0);",
    )
    .expect("seed v0");
    migrate_signed(&conn, &signer).expect("migrate to the tip");
    conn.execute(
        "INSERT INTO memories (id, tier, namespace, title, content, created_at, updated_at) \
         VALUES ('m-10157', 'long', 'ns-10157', 't', 'c', '2026-11-27T00:00:00Z', '2026-11-27T00:00:00Z')",
        [],
    )
    .expect("durable row");
    conn.execute(
        "DELETE FROM signed_events WHERE event_type = ?1",
        params![AGENT_CUTOVER_EVENT_TYPE],
    )
    .expect("drop genesis marker");
    conn.execute_batch(&format!(
        "DELETE FROM schema_version; INSERT INTO schema_version (version) VALUES ({V102_RUNG});"
    ))
    .expect("rewind to v102");
    conn.execute_batch("PRAGMA journal_mode=DELETE;")
        .expect("no wal");
}

#[test]
fn migrate_inner_refuses_a_keyless_bump_before_any_byte_10157() {
    let work = tempfile::Builder::new()
        .prefix("keyless-")
        .tempdir_in(scratch_root())
        .expect("work dir");
    let db_dir = work.path().join("db");
    let key_dir = work.path().join("keys");
    std::fs::create_dir_all(&db_dir).expect("db dir");
    let db = db_dir.join("v102-10157.db");
    make_v102(&db, &key_dir);

    let before = dir_bytes(&db_dir);
    let conn = Connection::open(&db).expect("reopen");
    let err = migrate_inner(&conn, || {
        Err::<&DaemonChainSigner, _>(DaemonKeyMissing::new(DaemonKeyCause::NoKeyDir, None))
    })
    .expect_err("a keyless ladder run is refused");
    let refusal = err
        .chain()
        .find_map(|e| e.downcast_ref::<DaemonKeyMissing>())
        .unwrap_or_else(|| panic!("not a DaemonKeyMissing refusal: {err:#}"));
    assert_eq!(refusal.cause(), DaemonKeyCause::NoKeyDir, "{err:#}");
    assert!(
        err.to_string().starts_with("daemon key missing: "),
        "the refusal names its class: {err:#}"
    );
    assert_eq!(version(&conn), V102_RUNG, "the stamp stays at 102");
    assert_eq!(markers(&conn), 0, "no marker was written");
    drop(conn);
    // No snapshot, no wal or shm, no byte of the database changed.
    assert_eq!(
        dir_bytes(&db_dir),
        before,
        "the database directory is byte-identical"
    );
}
