//! #9435 — a provenance / genesis read must never fold a storage query or
//! decode error into "absent" (rust-1-98 ERRORS-19; same class as #9418 and
//! #8868).
//!
//! Invariant, per fixed site: absent row or NULL column -> `Ok(None)` (or the
//! unchanged success path); a query / decode error -> `Err` carrying the
//! storage error text. Sites covered here (SQLite):
//!
//! * `db::read_cid_genesis` (the first instance, `.optional().unwrap_or(None)`)
//! * `read_memory_cid` (reached through `db::create_link` with the lineage DAG
//!   on: an unreadable `memories.cid` used to stamp a NULL `source_cid`)
//! * `lineage_edge_is_forward` (reached through `db::create_link`: an
//!   unreadable `created_at` used to answer "not forward" and ADMIT the edge)
//!
//! The lineage flag is a process-wide atomic, so the link cells serialize on
//! `FLAG_LOCK`. Every database lives under the clone's `.local-runs/`.

use std::path::PathBuf;
use std::sync::Mutex;

use ai_memory::db;
use ai_memory::models::{Memory, Tier};
use rusqlite::Connection;

static FLAG_LOCK: Mutex<()> = Mutex::new(());

const RUNS_DIR: &str = ".local-runs/provenance-read-error-surfaces-9435";
const NAMESPACE: &str = "provenance-9435";
const NEWER_STAMP: &str = "2026-06-30T00:00:00Z";
const OLDER_STAMP: &str = "2026-01-01T00:00:00Z";
const CHILD_ID: &str = "child-9435";
const PARENT_ID: &str = "parent-9435";
const RELATION: &str = "derived_from";
/// A BLOB stored where the code reads TEXT / a TEXT stored where it reads a
/// BLOB: rusqlite reports `InvalidColumnType` for both.
const UNREADABLE_BLOB_SQL: &str = "X'00FF'";
const UNREADABLE_TEXT_SQL: &str = "'not-a-blob'";
/// Exact rusqlite texts the folds used to swallow.
const ERR_GENESIS_TEXT: &str = "Invalid column type Text at index: 0, name: cid_genesis";
const ERR_CID_BLOB: &str = "Invalid column type Blob at index: 0, name: cid";
const ERR_CREATED_AT_BLOB: &str = "Invalid column type Blob at index: 0, name: created_at";

fn flag_guard() -> std::sync::MutexGuard<'static, ()> {
    FLAG_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn open_db(test: &str) -> Connection {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(RUNS_DIR);
    std::fs::create_dir_all(&dir).expect("create runs dir");
    let path = dir.join(format!("{test}.db"));
    let _ = std::fs::remove_file(&path);
    db::open(&path).expect("open explicit db")
}

fn mem(id: &str, created_at: &str) -> Memory {
    Memory {
        id: id.to_string(),
        title: format!("title {id}"),
        content: format!("content {id}"),
        namespace: NAMESPACE.to_string(),
        tier: Tier::Long,
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        metadata: serde_json::json!({ "agent_id": "ai:test@host" }),
        ..Default::default()
    }
}

fn seed_pair(conn: &Connection) {
    db::insert(conn, &mem(CHILD_ID, NEWER_STAMP)).expect("insert child");
    db::insert(conn, &mem(PARENT_ID, OLDER_STAMP)).expect("insert parent");
}

fn set_column(conn: &Connection, column: &str, value_sql: &str, id: &str) {
    conn.execute(
        &format!("UPDATE memories SET {column} = {value_sql} WHERE id = ?1"),
        [id],
    )
    .expect("poison column");
}

// ---- read_cid_genesis ------------------------------------------------

#[test]
fn genesis_unreadable_column_is_err_not_none() {
    let conn = open_db("genesis_unreadable");
    db::insert(&conn, &mem(CHILD_ID, NEWER_STAMP)).unwrap();
    set_column(&conn, "cid_genesis", UNREADABLE_TEXT_SQL, CHILD_ID);
    let err = db::read_cid_genesis(&conn, CHILD_ID).expect_err("decode error must surface");
    assert_eq!(err.to_string(), ERR_GENESIS_TEXT);
}

#[test]
fn genesis_absent_row_is_ok_none() {
    let conn = open_db("genesis_absent");
    assert_eq!(db::read_cid_genesis(&conn, "no-such-id").unwrap(), None);
}

#[test]
fn genesis_null_column_is_ok_none() {
    let conn = open_db("genesis_null");
    db::insert(&conn, &mem(CHILD_ID, NEWER_STAMP)).unwrap();
    set_column(&conn, "cid_genesis", "NULL", CHILD_ID);
    assert_eq!(db::read_cid_genesis(&conn, CHILD_ID).unwrap(), None);
}

// ---- read_memory_cid via create_link ------------------------------------

#[test]
fn link_unreadable_cid_is_err_not_null_mirror() {
    let _g = flag_guard();
    ai_memory::config::set_lineage_dag(true);
    let conn = open_db("link_cid_unreadable");
    seed_pair(&conn);
    set_column(&conn, "cid", UNREADABLE_BLOB_SQL, CHILD_ID);
    let res = db::create_link(&conn, CHILD_ID, PARENT_ID, RELATION);
    ai_memory::config::set_lineage_dag(false);
    let err = res.expect_err("cid decode error must surface");
    assert!(
        format!("{err:#}").contains(ERR_CID_BLOB),
        "unexpected error text: {err:#}"
    );
}

#[test]
fn link_null_cid_is_ok() {
    let _g = flag_guard();
    ai_memory::config::set_lineage_dag(true);
    let conn = open_db("link_cid_null");
    seed_pair(&conn);
    set_column(&conn, "cid", "NULL", CHILD_ID);
    let res = db::create_link(&conn, CHILD_ID, PARENT_ID, RELATION);
    ai_memory::config::set_lineage_dag(false);
    res.expect("a NULL cid is the legacy state and links cleanly");
}

// ---- lineage_edge_is_forward via create_link ------------------------------

#[test]
fn link_unreadable_created_at_is_err_not_admitted() {
    let _g = flag_guard();
    ai_memory::config::set_lineage_dag(true);
    let conn = open_db("link_created_at_unreadable");
    seed_pair(&conn);
    set_column(&conn, "created_at", UNREADABLE_BLOB_SQL, PARENT_ID);
    let res = db::create_link(&conn, CHILD_ID, PARENT_ID, RELATION);
    ai_memory::config::set_lineage_dag(false);
    let err = res.expect_err("created_at decode error must stop the link");
    assert!(
        format!("{err:#}").contains(ERR_CREATED_AT_BLOB),
        "unexpected error text: {err:#}"
    );
}
