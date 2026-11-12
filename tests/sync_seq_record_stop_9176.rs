// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #9176 B7 — record-stop and the `sync_seq` writers.
//!
//! Invariant: under record-stop no runtime path writes `sync_seq` state, and
//! opening a database (migration plus the open-time identity / restore bind)
//! still completes. The runtime writers (`regenerate_seq_epoch`,
//! `sync_pull_seq_set`) refuse with the exact typed reason and leave the
//! stored value unchanged; the open-time binders (`bind_node_identity`
//! behind `bind_at_open` on sqlite, `bind_sync_seq_node_identity` on
//! postgres) are the two reviewed B7 allowlist rows, and the structural pins
//! below keep them reachable from the open path only.
//!
//! Postgres has no runtime `sync_seq` writer: the puller's sequence cursor
//! lives in the puller's sqlite database on every deployment, so the
//! postgres half pins the open-time bind under record-stop.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use ai_memory::storage::StorageError;
use ai_memory::storage::record_stop::{SCOPE_RECORD_PLANE, actuate_sqlite};
use ai_memory::storage::sync_seq;

/// The operator principal every engage in this file names.
const OPERATOR: &str = "ai:operator-9176";
const LOCAL: &str = "ai:puller-9176";
const PEER: &str = "ai:peer-9176";
/// The cursor stored before the stop; the refused write tries `REFUSED_SEQ`.
const STORED_SEQ: i64 = 7;
const REFUSED_SEQ: i64 = 42;
const STORED_EPOCH: &str = "epoch-before-stop";
/// A node identity no real file carries (simulates a copied database).
const FOREIGN_IDENTITY: &str = "ino:copied-from-elsewhere";

fn scratch_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs/test-9176-record-stop");
    fs::create_dir_all(&root).expect("scratch root");
    root
}

fn counter(conn: &rusqlite::Connection) -> (String, Option<String>) {
    conn.query_row(
        "SELECT epoch, node_identity FROM sync_seq_counter WHERE id = 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("counter row")
}

fn engage(conn: &rusqlite::Connection) {
    assert!(
        actuate_sqlite(conn, true, OPERATOR, SCOPE_RECORD_PLANE).expect("engage record-stop"),
        "the engage changes state"
    );
}

/// The exact typed refusal of a gated `sync_seq` writer.
fn assert_record_stopped(err: &anyhow::Error, what: &str) {
    match err.downcast_ref::<StorageError>() {
        Some(StorageError::RecordStopped { issued_by, scope }) => {
            assert_eq!(issued_by, OPERATOR, "{what}: the stop names its operator");
            assert_eq!(
                scope, SCOPE_RECORD_PLANE,
                "{what}: the stop names its scope"
            );
        }
        other => panic!("{what}: expected StorageError::RecordStopped, got {other:?} ({err:#})"),
    }
}

#[test]
fn runtime_seq_writers_refuse_under_record_stop_sqlite_9176() {
    let dir = tempfile::tempdir_in(scratch_root()).expect("tempdir");
    let path = dir.path().join("runtime.db");
    let conn = ai_memory::db::open(&path).expect("open");
    sync_seq::sync_pull_seq_set(&conn, LOCAL, PEER, STORED_SEQ, STORED_EPOCH)
        .expect("store the cursor while running");
    let before_counter = counter(&conn);
    engage(&conn);

    let err = sync_seq::regenerate_seq_epoch(&conn).expect_err("regenerate under stop");
    assert_record_stopped(&err, "regenerate_seq_epoch");
    assert_eq!(
        counter(&conn),
        before_counter,
        "regenerate_seq_epoch: the stored epoch is unchanged"
    );

    let err = sync_seq::sync_pull_seq_set(&conn, LOCAL, PEER, REFUSED_SEQ, "epoch-after-stop")
        .expect_err("cursor write under stop");
    assert_record_stopped(&err, "sync_pull_seq_set");
    assert_eq!(
        sync_seq::sync_pull_seq_get(&conn, LOCAL, PEER).expect("cursor"),
        sync_seq::PullSeqCursor {
            last_seq: Some(STORED_SEQ),
            seq_epoch: Some(STORED_EPOCH.to_string()),
        },
        "sync_pull_seq_set: the stored cursor is unchanged"
    );
}

#[test]
fn open_binds_identity_and_consumes_restore_under_record_stop_sqlite_9176() {
    let dir = tempfile::tempdir_in(scratch_root()).expect("tempdir");
    let path = dir.path().join("open.db");
    let conn = ai_memory::db::open(&path).expect("first open");
    let (epoch0, identity0) = counter(&conn);
    let expected_identity = sync_seq::sqlite_node_identity(&path);
    assert_eq!(
        identity0, expected_identity,
        "the first open binds the identity"
    );
    engage(&conn);

    // A copy: the stored identity is not this file's.
    conn.execute(
        "UPDATE sync_seq_counter SET node_identity = ?1 WHERE id = 1",
        [FOREIGN_IDENTITY],
    )
    .expect("simulate a copied file");
    drop(conn);
    let conn = ai_memory::db::open(&path).expect("open + identity bind under record-stop");
    let (epoch1, identity1) = counter(&conn);
    assert_eq!(
        identity1, expected_identity,
        "the open rebinds the identity"
    );
    if expected_identity.is_some() {
        assert_ne!(epoch1, epoch0, "a copied file gets a fresh epoch");
    }
    drop(conn);

    // A restore: the armed sidecar is consumed and the epoch re-minted.
    sync_seq::arm_epoch_reset(&path).expect("arm the reset");
    let conn = ai_memory::db::open(&path).expect("open + restore bind under record-stop");
    let (epoch2, identity2) = counter(&conn);
    assert_ne!(epoch2, epoch1, "a restored file gets a fresh epoch");
    assert_eq!(
        identity2, expected_identity,
        "the restore keeps the identity"
    );
    assert!(
        !sync_seq::epoch_reset_marker_path(&path)
            .try_exists()
            .expect("stat sidecar"),
        "the sidecar is removed once the new epoch is committed"
    );
    // The plane is still stopped: the runtime writer still refuses.
    let err = sync_seq::regenerate_seq_epoch(&conn).expect_err("still stopped");
    assert_record_stopped(&err, "regenerate_seq_epoch after reopen");
    assert_eq!(
        counter(&conn).0,
        epoch2,
        "the epoch is unchanged by the refusal"
    );
}

#[cfg(feature = "sal-postgres")]
#[tokio::test]
async fn open_binds_identity_under_record_stop_postgres_9176() {
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset (postgres cell)");
        return;
    };
    let scratch = common::pg_barrier::ScratchDb::create(&url, "rs_seq_9176")
        .await
        .expect("create scratch database");
    let store = PostgresStore::connect(&scratch.url())
        .await
        .expect("first connect");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&scratch.url())
        .await
        .expect("raw pool");
    let read = || async {
        sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT epoch, node_identity FROM sync_seq_counter WHERE id = 1",
        )
        .fetch_one(&pool)
        .await
        .expect("counter row")
    };
    let (epoch0, identity0) = read().await;
    let identity0 = identity0.expect("the first connect binds the identity");
    let ctx = CallerContext::for_admin(OPERATOR);
    store
        .record_stop(&ctx, true, OPERATOR, SCOPE_RECORD_PLANE)
        .await
        .expect("engage record-stop");
    assert!(
        store
            .record_stop_status(&ctx)
            .await
            .expect("record_stop_status")
            .stopped,
        "the plane is stopped"
    );
    sqlx::query("UPDATE sync_seq_counter SET node_identity = $1 WHERE id = 1")
        .bind(FOREIGN_IDENTITY)
        .execute(&pool)
        .await
        .expect("simulate a restored instance");

    let reopened = PostgresStore::connect(&scratch.url())
        .await
        .expect("connect + identity bind under record-stop");
    let (epoch1, identity1) = read().await;
    assert_eq!(
        identity1.as_deref(),
        Some(identity0.as_str()),
        "the identity is rebound"
    );
    assert_ne!(epoch1, epoch0, "a changed instance gets a fresh epoch");

    reopened
        .record_stop(&ctx, false, OPERATOR, SCOPE_RECORD_PLANE)
        .await
        .expect("release record-stop");
    pool.close().await;
}

// ---- structural pins: the exemption stays open-time only ----

fn walk_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read_dir").flatten() {
        let p = entry.path();
        if p.is_dir() {
            walk_rs(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Does `line` mention `name` as a whole identifier?
fn mentions_ident(line: &str, name: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    line.match_indices(name).any(|(i, m)| {
        !line[..i].chars().next_back().is_some_and(is_ident)
            && !line[i + m.len()..].chars().next().is_some_and(is_ident)
    })
}

/// Every non-comment, non-declaration mention of `name` under src/, as
/// `path:line`.
fn call_sites(name: &str) -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    walk_rs(&root.join("src"), &mut files);
    files.sort();
    let mut sites = Vec::new();
    for f in &files {
        let text = fs::read_to_string(f).expect("read source");
        let rel = f
            .strip_prefix(root)
            .expect("under root")
            .to_string_lossy()
            .replace('\\', "/");
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//")
                || line.contains(&format!("fn {name}"))
                || !mentions_ident(line, name)
            {
                continue;
            }
            sites.push(format!("{rel}:{}", i + 1));
        }
    }
    sites
}

fn declaration(file: &str, name: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = fs::read_to_string(root.join(file)).expect("read source");
    src.lines()
        .find(|l| l.contains(&format!("fn {name}(")))
        .unwrap_or_else(|| panic!("{name} must exist in {file}"))
        .trim_start()
        .to_string()
}

/// The two allowlisted binders are private; the sqlite open entry is
/// `pub(super)` (only `crate::storage` can reach it), never wider.
#[test]
fn open_time_binders_are_not_public_9176() {
    let sqlite = declaration("src/storage/sync_seq.rs", "bind_node_identity");
    assert!(
        sqlite.starts_with("fn "),
        "#9176: the allowlisted sqlite binder must be private, found `{sqlite}`"
    );
    let entry = declaration("src/storage/sync_seq.rs", "bind_at_open");
    assert!(
        entry.starts_with("pub(super) fn "),
        "#9176: the open-time entry must be `pub(super)`, found `{entry}`"
    );
    let pg = declaration("src/store/postgres.rs", "bind_sync_seq_node_identity");
    assert!(
        pg.starts_with("async fn "),
        "#9176: the allowlisted postgres binder must be private, found `{pg}`"
    );
}

/// The exemption holds only because the binders run at open: pin each call
/// site. A new caller must be reviewed here.
#[test]
fn open_time_binder_call_sites_are_open_only_9176() {
    let sites = call_sites("bind_node_identity");
    assert_eq!(
        sites.len(),
        1,
        "#9176: bind_node_identity has exactly one caller (bind_at_open): {sites:?}"
    );
    assert!(
        sites[0].starts_with("src/storage/sync_seq.rs:"),
        "#9176: bind_node_identity is called only inside sync_seq.rs: {sites:?}"
    );
    let entry = call_sites("bind_at_open");
    assert_eq!(
        entry.len(),
        1,
        "#9176: one open-funnel call of bind_at_open: {entry:?}"
    );
    assert!(
        entry[0].starts_with("src/storage/connection.rs:"),
        "#9176: bind_at_open is called only from the open funnel: {entry:?}"
    );
    let pg = call_sites("bind_sync_seq_node_identity");
    assert_eq!(
        pg.len(),
        2,
        "#9176: bind_sync_seq_node_identity has exactly 2 callers (connect boot, migrate): {pg:?}"
    );
    assert!(
        pg.iter().all(|s| s.starts_with("src/store/postgres.rs:")),
        "#9176: the postgres binder is called only inside postgres.rs: {pg:?}"
    );
}

/// The runtime writers carry the gate call as their first statement.
#[test]
fn runtime_seq_writers_call_the_gate_9176() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = fs::read_to_string(root.join("src/storage/sync_seq.rs")).expect("sync_seq.rs");
    for name in ["regenerate_seq_epoch", "sync_pull_seq_set"] {
        let start = src
            .find(&format!("pub fn {name}("))
            .unwrap_or_else(|| panic!("{name} must exist"));
        let body_start = start + src[start..].find('{').expect("body");
        let first = src[body_start + 1..]
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .expect("first statement");
        assert_eq!(
            first, "crate::storage::record_stop::gate_storage_conn(conn)?;",
            "#9176: {name} must open with the record-stop gate"
        );
    }
}
