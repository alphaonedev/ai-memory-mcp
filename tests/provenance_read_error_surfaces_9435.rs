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
use ai_memory::db::schema_guard;
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
    assert_eq!(err.to_string(), ERR_CID_BLOB);
    assert_eq!(link_rows(&conn), 0, "no link row on a stopped write");
}

/// Security M3 — the TARGET endpoint's cid read must surface too (a fold on
/// the target side alone used to survive every cell).
#[test]
fn link_unreadable_target_cid_is_err_not_null_mirror() {
    let _g = flag_guard();
    ai_memory::config::set_lineage_dag(true);
    let conn = open_db("link_target_cid_unreadable");
    seed_pair(&conn);
    set_column(&conn, "cid", UNREADABLE_BLOB_SQL, PARENT_ID);
    let res = db::create_link(&conn, CHILD_ID, PARENT_ID, RELATION);
    ai_memory::config::set_lineage_dag(false);
    let err = res.expect_err("target cid decode error must surface");
    assert_eq!(err.to_string(), ERR_CID_BLOB);
    assert_eq!(link_rows(&conn), 0, "no link row on a stopped write");
}

fn link_rows(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM memory_links", [], |r| r.get(0))
        .expect("count links")
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
    assert_eq!(err.to_string(), ERR_CREATED_AT_BLOB);
    assert_eq!(link_rows(&conn), 0, "no link row on a stopped write");
}

// ---- #9484: an unparsable created_at is an Err, never "not forward" -------

/// Readable TEXT that is not RFC 3339: each one used to answer "not forward"
/// and ADMIT the edge (security F1, #9484).
const UNPARSABLE_CREATED_AT: &[&str] = &["", "not-a-timestamp", "2026-13-40T00:00:00Z"];

fn err_unparsable_created_at(id: &str) -> String {
    format!(
        "lineage guard: memory {id}: created_at is not an RFC 3339 timestamp, so the edge \
         direction cannot be established; the link is refused"
    )
}

fn unparsable_created_at_case(test: &str, poisoned: &str) {
    for (n, value) in UNPARSABLE_CREATED_AT.iter().enumerate() {
        let _g = flag_guard();
        ai_memory::config::set_lineage_dag(true);
        let conn = open_db(&format!("{test}_{n}"));
        seed_pair(&conn);
        set_column(&conn, "created_at", &format!("'{value}'"), poisoned);
        let res = db::create_link(&conn, CHILD_ID, PARENT_ID, RELATION);
        ai_memory::config::set_lineage_dag(false);
        let err = res.expect_err("an unparsable created_at must stop the link");
        assert_eq!(
            err.to_string(),
            err_unparsable_created_at(poisoned),
            "value {value:?}"
        );
        assert_eq!(link_rows(&conn), 0, "value {value:?}: no link row");
    }
}

#[test]
fn link_unparsable_source_created_at_is_err_and_writes_no_row() {
    unparsable_created_at_case("link_unparsable_source", CHILD_ID);
}

#[test]
fn link_unparsable_target_created_at_is_err_and_writes_no_row() {
    unparsable_created_at_case("link_unparsable_target", PARENT_ID);
}

/// The forward (older -> newer) refusal is unchanged by #9484.
#[test]
fn link_forward_edge_is_still_refused_as_a_cycle() {
    let _g = flag_guard();
    ai_memory::config::set_lineage_dag(true);
    let conn = open_db("link_forward_refused");
    seed_pair(&conn);
    let res = db::create_link(&conn, PARENT_ID, CHILD_ID, RELATION);
    ai_memory::config::set_lineage_dag(false);
    let err = res.expect_err("forward edge refused");
    assert_eq!(
        err.to_string(),
        format!(
            "{}: {PARENT_ID} --reflects_on--> {CHILD_ID} would close a cycle",
            ai_memory::db::LINK_CYCLE_ERR_PREFIX
        )
    );
    assert_eq!(link_rows(&conn), 0);
}

/// The equal-instant path is unchanged: a clean edge is admitted, and the
/// reverse edge that would close a 2-cycle is refused.
#[test]
fn link_equal_instant_admits_clean_edge_and_refuses_the_cycle() {
    let _g = flag_guard();
    ai_memory::config::set_lineage_dag(true);
    let conn = open_db("link_equal_instant");
    db::insert(&conn, &mem(CHILD_ID, NEWER_STAMP)).expect("insert child");
    db::insert(&conn, &mem(PARENT_ID, NEWER_STAMP)).expect("insert parent");
    let first = db::create_link(&conn, CHILD_ID, PARENT_ID, RELATION);
    let second = db::create_link(&conn, PARENT_ID, CHILD_ID, RELATION);
    ai_memory::config::set_lineage_dag(false);
    first.expect("clean equal-instant edge admitted");
    let err = second.expect_err("cycle-closing equal-instant edge refused");
    assert_eq!(
        err.to_string(),
        format!(
            "{}: {PARENT_ID} --reflects_on--> {CHILD_ID} would close a cycle",
            ai_memory::db::LINK_CYCLE_ERR_PREFIX
        )
    );
    assert_eq!(link_rows(&conn), 1);
}

// ---- cli::verify::run (the `verify-reflection-chain` root cid line) --------

/// The verdict line `verify-reflection-chain` prints for a stamped root.
const VERIFY_CID_LINE: &str = "cid_verified:   ";

fn scratch_path(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(RUNS_DIR);
    std::fs::create_dir_all(&dir).expect("create runs dir");
    let path = dir.join(format!("{test}.db"));
    let _ = std::fs::remove_file(&path);
    path
}

/// Run `verify-reflection-chain` (text format) on `path`, returning the
/// result and the stdout text.
fn run_verify(path: &std::path::Path) -> (anyhow::Result<i32>, String) {
    let args = ai_memory::cli::verify::VerifyChainArgs {
        memory_id: CHILD_ID.to_string(),
        format: "text".to_string(),
        include_signed_events: false,
        cid: false,
    };
    let mut stdout = Vec::<u8>::new();
    let mut stderr = Vec::<u8>::new();
    let res = {
        let mut out = ai_memory::cli::CliOutput::from_std(&mut stdout, &mut stderr);
        ai_memory::cli::verify::run(path, &args, &mut out)
    };
    (res, String::from_utf8(stdout).expect("utf8 stdout"))
}

fn seeded_verify_db(test: &str, genesis_sql: Option<&str>) -> PathBuf {
    let path = scratch_path(test);
    let conn = db::open(&path).expect("open explicit db");
    db::insert(&conn, &mem(CHILD_ID, NEWER_STAMP)).expect("insert root");
    if let Some(sql) = genesis_sql {
        set_column(&conn, "cid_genesis", sql, CHILD_ID);
    }
    path
}

/// #9505 (3-agent vote (71472661), B + J1) — an unreadable genesis fails the
/// verb as a failed VERIFICATION (exit 2, a named class on the verdict line),
/// not as a generic `Err` after a passing-looking report; the full matrix
/// lives in `tests/verify_chain_genesis_exit_code_9505.rs`.
#[test]
fn verify_unreadable_genesis_is_exit_2_not_skipped_line() {
    let path = seeded_verify_db("verify_unreadable", Some(UNREADABLE_TEXT_SQL));
    let (res, stdout) = run_verify(&path);
    assert_eq!(res.expect("a failed check is an exit code"), 2);
    assert!(
        stdout.contains(&format!("{VERIFY_CID_LINE}unreadable (decode_error)")),
        "verdict line names the class: {stdout}"
    );
}

#[test]
fn verify_readable_genesis_prints_cid_verified_true() {
    let path = seeded_verify_db("verify_readable", None);
    let (res, stdout) = run_verify(&path);
    assert_eq!(res.expect("verify runs"), 0);
    assert!(
        stdout.contains(&format!("{VERIFY_CID_LINE}true")),
        "missing verdict line: {stdout}"
    );
}

#[test]
fn verify_null_genesis_is_ok_without_cid_line() {
    let path = seeded_verify_db("verify_null", Some("NULL"));
    let (res, stdout) = run_verify(&path);
    assert_eq!(res.expect("NULL genesis is not an error"), 0);
    assert!(
        !stdout.contains(VERIFY_CID_LINE),
        "no genesis, no line: {stdout}"
    );
}

// ---- form A: a schema older than v74 is a NAMED error (ruling 8c59363f) ----

const ERR_GENESIS_COLUMN_MISSING: &str = "provenance column memories.cid_genesis is missing: \
this database is on a schema older than v74 (the content-id columns). Repair: \
`ai-memory migrate --in-place` or start the daemon, then re-run.";
const PRE_V74_STAMP: i64 = 73;
const DROP_PRE_V74_COLUMNS_SQL: &[&str] = &[
    "DROP INDEX IF EXISTS idx_memories_cid",
    "ALTER TABLE memories DROP COLUMN cid_genesis",
    "ALTER TABLE memories DROP COLUMN cid",
];
const ERR_BEHIND_READ_ONLY_MARKER: &str = "BEHIND this binary";

#[test]
fn genesis_missing_column_is_named_schema_error_not_none() {
    let path = scratch_path("genesis_missing_column");
    let conn = Connection::open(&path).expect("open bare db");
    conn.execute_batch("CREATE TABLE memories (id TEXT PRIMARY KEY)")
        .expect("bare table without the v74 columns");
    let err = db::read_cid_genesis(&conn, CHILD_ID).expect_err("missing column must not be None");
    assert_eq!(err.to_string(), ERR_GENESIS_COLUMN_MISSING);
}

/// Build a v73-shaped scratch database: a migrated store holding the seeded
/// pair, with the v74 columns dropped and the stamp set to a REAL 73 (security
/// r1: deleting the row produced an unstamped store, not a v73 one).
fn v73_shaped_db(test: &str) -> PathBuf {
    let path = scratch_path(test);
    let conn = db::open(&path).expect("open explicit db");
    seed_pair(&conn);
    drop_pre_v74_columns(&conn);
    set_stamp(&conn, PRE_V74_STAMP);
    path
}

fn drop_pre_v74_columns(conn: &Connection) {
    for sql in DROP_PRE_V74_COLUMNS_SQL {
        conn.execute(sql, [])
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }
}

fn set_stamp(conn: &Connection, stamp: i64) {
    let n = conn
        .execute("UPDATE schema_version SET version = ?1", [stamp])
        .expect("set stamp");
    assert_eq!(n, 1, "one stamp row");
}

fn read_stamp(conn: &Connection) -> i64 {
    conn.query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .expect("read stamp")
}

#[test]
fn pre_v74_read_only_open_is_refused_before_any_provenance_read() {
    let path = v73_shaped_db("pre_v74_read_only");
    let err = db::open_existing_read_only(&path).expect_err("behind stamp is refused");
    let expected = schema_guard::SchemaBehindReadOnly::new(
        PRE_V74_STAMP,
        schema_guard::BACKEND_SQLITE,
        &path.display().to_string(),
    );
    assert_eq!(err.to_string(), expected.to_string());
    assert!(expected.detail.contains(ERR_BEHIND_READ_ONLY_MARKER));
    assert_eq!(expected.observed, PRE_V74_STAMP);
}

// ---- #9496: the classifier names only the cause it read (invariant B) -----

const ROOT_NO_SUCH_GENESIS: &str =
    "no such column: cid_genesis in SELECT cid_genesis FROM memories WHERE id = ?1 at offset 7";
const ROOT_NO_SUCH_MEMORIES: &str = "no such table: memories";
/// The SQLite result code under every prepare failure above.
const ROOT_SQLITE_CODE_1: &str = "Error code 1: SQL error or missing database";

/// The causes below the top message: the rusqlite error, then its code
/// (ERRORS-11: kept as `source()`, not rendered into the top text).
fn causes(err: &anyhow::Error) -> Vec<String> {
    err.chain().skip(1).map(ToString::to_string).collect()
}

/// A REAL v73 store (stamp row = 73): the pre-v74 text, unchanged.
#[test]
fn genesis_missing_column_on_real_v73_stamp_is_pre_v74_error() {
    let path = v73_shaped_db("genesis_real_v73");
    let conn = Connection::open(&path).expect("raw open, no migration");
    assert_eq!(read_stamp(&conn), PRE_V74_STAMP);
    let err = db::read_cid_genesis(&conn, CHILD_ID).expect_err("missing column is an error");
    assert_eq!(err.to_string(), ERR_GENESIS_COLUMN_MISSING);
    assert_eq!(causes(&err), [ROOT_NO_SUCH_GENESIS, ROOT_SQLITE_CODE_1]);
}

/// Stamp at the tip (>= v74) with the column gone: a DISTINCT error that does
/// not tell the operator to migrate (#9496).
#[test]
fn genesis_missing_column_at_current_stamp_is_distinct_not_migrate() {
    let path = scratch_path("genesis_at_tip_stamp");
    let conn = db::open(&path).expect("open explicit db");
    seed_pair(&conn);
    drop_pre_v74_columns(&conn);
    let tip = ai_memory::db::current_schema_version_for_tests();
    assert_eq!(read_stamp(&conn), tip);
    let err = db::read_cid_genesis(&conn, CHILD_ID).expect_err("missing column is an error");
    assert_eq!(
        err.to_string(),
        format!(
            "provenance column memories.cid_genesis is missing, but this database is stamped \
             schema v{tip}, which has it (added at v74): the stamp and the table shape \
             disagree, and a migrating open does not re-add the column. Repair: restore the \
             database from a backup, then re-run."
        )
    );
    assert!(!err.to_string().contains("migrate"), "no migrate advice");
    assert_eq!(causes(&err), [ROOT_NO_SUCH_GENESIS, ROOT_SQLITE_CODE_1]);
}

/// Exactly v74 is already "has the column": the boundary is `>=`, not `>`.
#[test]
fn genesis_missing_column_at_stamp_74_is_distinct_not_migrate() {
    let path = scratch_path("genesis_at_stamp_74");
    let conn = db::open(&path).expect("open explicit db");
    seed_pair(&conn);
    drop_pre_v74_columns(&conn);
    set_stamp(&conn, PRE_V74_STAMP + 1);
    let err = db::read_cid_genesis(&conn, CHILD_ID).expect_err("missing column is an error");
    assert!(
        err.to_string().starts_with(
            "provenance column memories.cid_genesis is missing, but this database is stamped \
             schema v74, which has it"
        ),
        "unexpected: {err:#}"
    );
}

/// The stamp cannot be read: its own error, no cause named.
#[test]
fn genesis_missing_column_with_unreadable_stamp_is_own_error() {
    let path = scratch_path("genesis_unreadable_stamp");
    let conn = Connection::open(&path).expect("open bare db");
    conn.execute_batch(
        "CREATE TABLE memories (id TEXT PRIMARY KEY);
         CREATE TABLE schema_version (version TEXT);
         INSERT INTO schema_version VALUES ('not-a-version');",
    )
    .expect("store with an unreadable stamp");
    let err = db::read_cid_genesis(&conn, CHILD_ID).expect_err("missing column is an error");
    assert_eq!(
        err.to_string(),
        "provenance column memories.cid_genesis is missing and the recorded schema version \
         cannot be read, so the cause is not established. Inspect the database before any \
         repair."
    );
    let chain: Vec<String> = err.chain().map(ToString::to_string).collect();
    assert_eq!(
        chain[1..],
        [
            ROOT_NO_SUCH_GENESIS.to_string(),
            "read the recorded schema version".to_string(),
            "Invalid column type Text at index: 0, name: COALESCE(MAX(version), 0)".to_string(),
        ]
    );
}

/// A populated store whose stamp row says 0: its own error, no cause named.
#[test]
fn genesis_missing_column_with_zeroed_stamp_is_own_error() {
    let path = scratch_path("genesis_zeroed_stamp");
    let conn = db::open(&path).expect("open explicit db");
    seed_pair(&conn);
    drop_pre_v74_columns(&conn);
    set_stamp(&conn, 0);
    let err = db::read_cid_genesis(&conn, CHILD_ID).expect_err("missing column is an error");
    assert_eq!(
        err.to_string(),
        "provenance column memories.cid_genesis is missing and the recorded schema version is \
         v0, which no migration writes, so the cause is not established. Inspect the database \
         before any repair."
    );
}

/// No `memories` table at all: never "older than v74".
#[test]
fn genesis_with_no_memories_table_is_own_error() {
    let path = scratch_path("genesis_no_memories_table");
    let conn = Connection::open(&path).expect("open bare db");
    let err = db::read_cid_genesis(&conn, CHILD_ID).expect_err("no table is an error");
    assert_eq!(
        err.to_string(),
        "provenance read of memories.cid_genesis failed: the memories table does not exist in \
         this database. Check the database path."
    );
    assert_eq!(causes(&err), [ROOT_NO_SUCH_MEMORIES, ROOT_SQLITE_CODE_1]);
}

/// Security M7 / code M7: `read_memory_cid` (the `memories.cid` read in front
/// of a lineage link) is classified too, and names `cid`, not `cid_genesis`.
#[test]
fn link_on_real_v73_store_names_the_cid_column() {
    let _g = flag_guard();
    ai_memory::config::set_lineage_dag(true);
    let path = v73_shaped_db("link_real_v73");
    let conn = Connection::open(&path).expect("raw open, no migration");
    let res = db::create_link(&conn, CHILD_ID, PARENT_ID, RELATION);
    ai_memory::config::set_lineage_dag(false);
    let err = res.expect_err("missing cid column must stop the link");
    assert_eq!(
        err.to_string(),
        "provenance column memories.cid is missing: this database is on a schema older than \
         v74 (the content-id columns). Repair: `ai-memory migrate --in-place` or start the \
         daemon, then re-run."
    );
    assert_eq!(link_rows(&conn), 0);
}

// ---- import: the backfill cid read surfaces and names the link -------------

/// Security M2 / code M6: a legacy bundle (no cids on the links) makes the
/// importer BACKFILL each endpoint's `memories.cid`; an unreadable one must
/// stop the import and name the link, never import a NULL mirror.
fn import_with_unreadable_endpoint_cid(test: &str, poisoned: &str) -> String {
    use ai_memory::portability::{emit, import};
    let _g = flag_guard();
    ai_memory::config::set_lineage_dag(true);
    let src = open_db(&format!("{test}_src"));
    seed_pair(&src);
    db::create_link(&src, CHILD_ID, PARENT_ID, RELATION).expect("source link");
    let envelope = emit::build_full_envelope(&src, "src", NEWER_STAMP).expect("export");
    let json = serde_json::to_string(&envelope).expect("serialize");
    let mut parsed: emit::ExportEnvelope = serde_json::from_str(&json).expect("parse");
    for l in &mut parsed.links {
        l.source_cid = None;
        l.target_cid = None;
    }
    let dst = open_db(&format!("{test}_dst"));
    dst.execute_batch(&format!(
        "CREATE TRIGGER poison_cid AFTER INSERT ON memories WHEN NEW.id = '{poisoned}' \
         BEGIN UPDATE memories SET cid = {UNREADABLE_BLOB_SQL} WHERE id = NEW.id; END;"
    ))
    .expect("poison trigger");
    let opts = import::ImportOptions {
        trust_source: true,
        caller_agent_id: "importer".into(),
        ..import::ImportOptions::default()
    };
    let res = import::import_full_envelope(&dst, &parsed, &opts);
    ai_memory::config::set_lineage_dag(false);
    let err = res.expect_err("an unreadable endpoint cid must stop the import");
    assert_eq!(link_rows(&dst), 0, "no link row imported");
    format!("{err:#}")
}

#[test]
fn import_unreadable_source_cid_is_err_naming_the_link() {
    let got = import_with_unreadable_endpoint_cid("import_source_cid", CHILD_ID);
    assert_eq!(
        got,
        format!(
            "import link {CHILD_ID}->{PARENT_ID} ({RELATION}): read source cid: {ERR_CID_BLOB}"
        )
    );
}

#[test]
fn import_unreadable_target_cid_is_err_naming_the_link() {
    let got = import_with_unreadable_endpoint_cid("import_target_cid", PARENT_ID);
    assert_eq!(
        got,
        format!(
            "import link {CHILD_ID}->{PARENT_ID} ({RELATION}): read target cid: {ERR_CID_BLOB}"
        )
    );
}

// ---- SAL: SqliteStore::verify surfaces the genesis read (code M8) ---------

#[cfg(feature = "sal")]
#[tokio::test]
async fn store_verify_unreadable_genesis_is_err_not_unverified() {
    use ai_memory::store::sqlite::SqliteStore;
    use ai_memory::store::{CallerContext, MemoryStore};
    let path = seeded_verify_db("store_verify_unreadable", Some(UNREADABLE_TEXT_SQL));
    let store = SqliteStore::open(&path).expect("open store");
    let err = store
        .verify(&CallerContext::for_agent("ai:test@host"), CHILD_ID)
        .await
        .expect_err("an unreadable genesis must fail verify");
    assert_eq!(
        err.to_string(),
        format!("underlying backend error: {ERR_GENESIS_TEXT}")
    );
}

#[test]
fn pre_v74_migrating_open_backfills_the_genesis_so_the_read_is_ok_some() {
    let path = v73_shaped_db("pre_v74_migrating");
    // `db::open` is the open every verb that reads provenance uses (verify,
    // import, link create): on a real v73 stamp it runs the v74 step, which
    // re-adds the column and backfills it, so the read never sees the
    // missing column. The backfill is the genesis a store that never lost
    // the column holds for the same row.
    let conn = db::open(&path).expect("migration must not need the v74 column");
    let intact = db::open(&scratch_path("pre_v74_migrating_intact")).expect("open intact db");
    seed_pair(&intact);
    let expected = db::read_cid_genesis(&intact, CHILD_ID)
        .expect("intact read")
        .expect("an intact store holds a genesis");
    assert_eq!(
        db::read_cid_genesis(&conn, CHILD_ID).expect("migrated read"),
        Some(expected)
    );
}

// ---- PostgreSQL twin: consolidate source cid read -------------------------

#[cfg(feature = "sal-postgres")]
#[path = "common/pg_barrier.rs"]
mod pg_barrier;

#[cfg(feature = "sal-postgres")]
mod pg_twin {
    use ai_memory::models::{Memory, Tier};
    use ai_memory::store::postgres::PostgresStore;
    use ai_memory::store::{CallerContext, MemoryStore};

    use super::pg_barrier;

    const SCRATCH_PREFIX: &str = "prov9435";
    const SOURCE_COUNT: usize = 2;
    const AGENT: &str = "ai:test@host";
    /// A NON-NULL integer in `memories.cid`: a NULL would decode (sqlx skips the type check on NULL).
    const POISON_CID_SQL: &str = "ALTER TABLE memories ALTER COLUMN cid TYPE integer USING 1";
    const NULL_CID_SQL: &str = "UPDATE memories SET cid = NULL";
    const ERR_PG_CID_DECODE: &str = "backend unavailable: postgres: read source cid: error occurred while decoding column \"cid\": mismatched types; Rust type `core::option::Option<alloc::string::String>` (as SQL type `TEXT`) is not compatible with SQL type `INT4`";

    fn mem(id: &str, ns: &str) -> Memory {
        Memory {
            id: id.to_string(),
            namespace: ns.to_string(),
            title: format!("t {id}"),
            content: format!("content {id}"),
            created_at: super::NEWER_STAMP.to_string(),
            updated_at: super::NEWER_STAMP.to_string(),
            metadata: serde_json::json!({ "agent_id": AGENT }),
            ..Memory::default()
        }
    }

    async fn seeded(url: &str) -> (pg_barrier::ScratchDb, PostgresStore, Vec<String>, String) {
        let scratch = pg_barrier::ScratchDb::create(url, SCRATCH_PREFIX)
            .await
            .expect("create scratch database");
        let store = PostgresStore::connect(&scratch.url())
            .await
            .expect("connect scratch database");
        let ctx = CallerContext::for_agent(AGENT);
        let ns = format!("prov-9435-{}", uuid::Uuid::new_v4());
        let mut ids = Vec::new();
        for _ in 0..SOURCE_COUNT {
            let id = uuid::Uuid::new_v4().to_string();
            store
                .store(&ctx, &mem(&id, &ns))
                .await
                .expect("store source");
            ids.push(id);
        }
        (scratch, store, ids, ns)
    }

    async fn run_consolidate(
        store: &PostgresStore,
        ids: &[String],
        ns: &str,
    ) -> Result<String, ai_memory::store::StoreError> {
        let ctx = CallerContext::for_agent(AGENT);
        store
            .consolidate(
                &ctx,
                ids,
                "merged",
                "merged body",
                ns,
                &Tier::Long,
                "consolidation",
                AGENT,
            )
            .await
    }

    #[tokio::test]
    async fn pg_consolidate_unreadable_source_cid_is_err() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let (_scratch, store, ids, ns) = seeded(&url).await;
        sqlx::query(POISON_CID_SQL)
            .execute(store.pool())
            .await
            .expect("poison cid column");
        let err = run_consolidate(&store, &ids, &ns)
            .await
            .expect_err("cid decode error must surface");
        assert_eq!(err.to_string(), ERR_PG_CID_DECODE);
    }

    #[tokio::test]
    async fn pg_consolidate_null_source_cid_is_ok() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        let (_scratch, store, ids, ns) = seeded(&url).await;
        sqlx::query(NULL_CID_SQL)
            .execute(store.pool())
            .await
            .expect("null cids");
        run_consolidate(&store, &ids, &ns)
            .await
            .expect("NULL source cids consolidate cleanly");
    }

    // ---- #9484 PostgreSQL twin: the lineage guard's created_at read -------

    /// The PG column is TIMESTAMPTZ, so each unparsable text is refused at
    /// write with the database's own named reason; it can never reach the
    /// guard as "not forward".
    const PG_UNPARSABLE_CREATED_AT: &[(&str, &str)] = &[
        (
            "",
            "error returned from database: invalid input syntax for type timestamp with time zone: \"\"",
        ),
        (
            "not-a-timestamp",
            "error returned from database: invalid input syntax for type timestamp with time zone: \"not-a-timestamp\"",
        ),
        (
            "2026-13-40T00:00:00Z",
            "error returned from database: date/time field value out of range: \"2026-13-40T00:00:00Z\"",
        ),
    ];
    /// The only way an unparsable `created_at` reaches the PG guard: the column
    /// itself no longer decodes as a timestamp.
    const PG_TEXT_CREATED_AT_SQL: &str = "ALTER TABLE memories ALTER COLUMN created_at DROP DEFAULT, \
         ALTER COLUMN created_at TYPE text USING 'not-a-timestamp'";
    const ERR_PG_GUARD_CREATED_AT: &str = "backend unavailable: postgres: lineage guard created_at fetch: error occurred while decoding column 1: mismatched types; Rust type `chrono::datetime::DateTime<chrono::offset::utc::Utc>` (as SQL type `TIMESTAMPTZ`) is not compatible with SQL type `TEXT`";
    const COUNT_LINKS_SQL: &str = "SELECT count(*) FROM memory_links";

    fn lineage_link(source: &str, target: &str) -> ai_memory::models::MemoryLink {
        ai_memory::models::MemoryLink {
            source_id: source.to_string(),
            target_id: target.to_string(),
            relation: ai_memory::models::MemoryLinkRelation::DerivedFrom,
            created_at: super::NEWER_STAMP.to_string(),
            valid_from: None,
            valid_until: None,
            observed_by: None,
            signature: None,
            attest_level: None,
            source_cid: None,
            target_cid: None,
        }
    }

    async fn link_rows(store: &PostgresStore) -> i64 {
        let (n,): (i64,) = sqlx::query_as(COUNT_LINKS_SQL)
            .fetch_one(store.pool())
            .await
            .expect("count links");
        n
    }

    /// Run `body` on its own runtime with the lineage flag on, holding the
    /// flag lock outside any `.await` (CONCURRENCY-20).
    fn with_lineage_flag<F: std::future::Future<Output = ()>>(body: F) {
        let _g = super::flag_guard();
        ai_memory::config::set_lineage_dag(true);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(body);
        ai_memory::config::set_lineage_dag(false);
    }

    #[test]
    fn pg_unparsable_created_at_is_refused_at_write_with_a_named_reason() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        with_lineage_flag(async move {
            let (_scratch, store, ids, _ns) = seeded(&url).await;
            for (value, reason) in PG_UNPARSABLE_CREATED_AT {
                let sql = format!("UPDATE memories SET created_at = '{value}' WHERE id = $1");
                let err = sqlx::query(&sql)
                    .bind(&ids[0])
                    .execute(store.pool())
                    .await
                    .expect_err("an unparsable created_at must not be stored");
                assert_eq!(err.to_string(), *reason, "value {value:?}");
            }
            assert_eq!(link_rows(&store).await, 0);
        });
    }

    #[test]
    fn pg_undecodable_created_at_is_err_and_writes_no_row() {
        let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
            eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL not set");
            return;
        };
        with_lineage_flag(async move {
            let (_scratch, store, ids, _ns) = seeded(&url).await;
            sqlx::query(PG_TEXT_CREATED_AT_SQL)
                .execute(store.pool())
                .await
                .expect("turn created_at into undecodable text");
            let err = store
                .link(
                    &CallerContext::for_agent(AGENT),
                    &lineage_link(&ids[0], &ids[1]),
                )
                .await
                .expect_err("an undecodable created_at must stop the link");
            assert_eq!(err.to_string(), ERR_PG_GUARD_CREATED_AT);
            assert_eq!(link_rows(&store).await, 0, "no link row on a stopped write");
        });
    }
}
