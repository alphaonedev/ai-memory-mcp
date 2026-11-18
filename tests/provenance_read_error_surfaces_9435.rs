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

#[test]
fn verify_unreadable_genesis_is_err_not_skipped_line() {
    let path = seeded_verify_db("verify_unreadable", Some(UNREADABLE_TEXT_SQL));
    let (res, stdout) = run_verify(&path);
    let err = res.expect_err("an unreadable genesis must fail the verb");
    assert_eq!(err.to_string(), ERR_GENESIS_TEXT);
    assert!(
        !stdout.contains(VERIFY_CID_LINE),
        "no verdict line: {stdout}"
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

/// Build a v73-shaped scratch database: a migrated store with the v74 columns
/// dropped and the stamp rolled back to 73.
fn v73_shaped_db(test: &str) -> PathBuf {
    let path = scratch_path(test);
    let conn = db::open(&path).expect("open explicit db");
    for sql in DROP_PRE_V74_COLUMNS_SQL {
        conn.execute(sql, [])
            .unwrap_or_else(|e| panic!("{sql}: {e}"));
    }
    conn.execute(
        "DELETE FROM schema_version WHERE version > ?1",
        [PRE_V74_STAMP],
    )
    .expect("roll back stamp");
    path
}

#[test]
fn pre_v74_read_only_open_is_refused_before_any_provenance_read() {
    let path = v73_shaped_db("pre_v74_read_only");
    let err = db::open_existing_read_only(&path).expect_err("behind stamp is refused");
    assert!(
        err.to_string().contains(ERR_BEHIND_READ_ONLY_MARKER),
        "unexpected refusal: {err:#}"
    );
}

#[test]
fn pre_v74_migrating_open_adds_the_columns_so_the_read_is_ok_none() {
    let path = v73_shaped_db("pre_v74_migrating");
    // `db::open` is the open every verb that reads provenance uses (verify,
    // import, link create): it migrates first, so the read never sees the
    // missing column. The migration itself never reads the column.
    let conn = db::open(&path).expect("migration must not need the v74 column");
    assert_eq!(db::read_cid_genesis(&conn, CHILD_ID).unwrap(), None);
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
}
