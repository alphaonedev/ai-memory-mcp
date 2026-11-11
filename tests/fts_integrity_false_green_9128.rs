// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#9128](https://github.com/alphaonedev/ai-memory-mcp/issues/9128) —
//! LOST-FIX of [#4036](https://github.com/alphaonedev/ai-memory-mcp/issues/4036):
//! the FTS integrity worker ran the DEFAULT form of FTS5 `'integrity-check'`,
//! which only walks the index's own b-tree. `memories_fts` is an
//! external-content table, and the default form never compares its postings
//! with the `memories` rows, so `/health` answered `ok` while a live memory
//! was missing from keyword recall.
//!
//! Class (integrity-false-green): a background integrity worker or a health
//! surface answers green when the derived state it names does not match the
//! rows. Invariant pinned here, by BEHAVIOUR and never by matching SQL text:
//!
//! 1. Green means compared: every drift arm below (a live row missing from
//!    the index, postings left behind by an erased row, stale postings of an
//!    edited row) fails the deep check and turns every surface not-ok:
//!    the in-process verdict funnel, HTTP `/api/v1/health`, HTTP
//!    `/api/v1/monitoring/status` and `ai-memory doctor`.
//! 2. A clean corpus still verifies (the control arm), so the cells are not
//!    vacuous.
//! 3. At [`BOUND_ROWS`] rows (and only that size is pinned here) the deep
//!    check finishes inside [`WRITER_BLOCK_BOUND`], the writers'
//!    `busy_timeout`. The check holds the writer lock for a time linear in
//!    the corpus with no runtime cap, so a corpus several times larger can
//!    exceed that bound; the runtime bound is tracked as PRE-EXISTING #9181
//!    (and #9161).
//! 4. A repaired index returns to `ok` only through a fresh check.
//!
//! The first cell is the original #4036 regression test, re-landed from
//! commit d228eb6c97ad08576c1ad3108f4cea0305395482.

use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ai_memory::background::fts_integrity::{
    IntegrityStatus, Outcome, Verdict, classify_error, run_once,
};
use ai_memory::models::{Memory, Tier};
use ai_memory::storage as db;

mod common;

/// Rows every drift arm seeds. Small: the arms are about correctness.
const ARM_ROWS: usize = 5;
/// Index of the seeded row an arm damages.
const DAMAGED_ROW: usize = 0;
/// Rowid used for a ghost posting no `memories` row owns.
const GHOST_ROWID: i64 = 9_128_000;
/// Rows for the cost cell (invariant 3: one 100K-row bound).
const BOUND_ROWS: usize = 100_000;
/// The production writer `busy_timeout` (`src/storage/connection.rs`). The
/// deep check takes the WAL writer lock for its whole run, so a check longer
/// than this makes a concurrent writer fail with `SQLITE_BUSY`. The bound is
/// asserted at [`BOUND_ROWS`] only; it is not a guarantee for larger corpora
/// (PRE-EXISTING #9181).
const WRITER_BLOCK_BOUND: Duration = Duration::from_millis(5_000);
/// Daemon checker cadence for the transport cells, in whole seconds. One
/// second keeps the startup spread at or under one second.
const CHECK_INTERVAL_SECS: &str = "1";
/// Hang guard for the boot and the first completed verdict (not a product
/// assertion).
const VERDICT_HANG_GUARD: Duration = Duration::from_mins(1);
/// Poll step while waiting for the daemon to publish an observable verdict.
const POLL_STEP: Duration = Duration::from_millis(100);
/// Wire tags asserted on the transports.
const WIRE_FAILED: &str = "failed";
const WIRE_OK: &str = "ok";
const WIRE_PENDING: &str = "pending";
const WIRE_ERROR: &str = "error";
#[cfg(feature = "sal-postgres")]
const WIRE_DISABLED: &str = "disabled";
const REASON_INDEX_FAILED: &str = "index_failed";
const HTTP_OK: u16 = 200;
const HTTP_UNAVAILABLE: u16 = 503;

const ROUTE_HEALTH: &str = "/api/v1/health";
const ROUTE_STATUS: &str = "/api/v1/monitoring/status";
/// Test-only shared key so the daemon accepts an authenticated monitoring
/// read (`/api/v1/monitoring/status` refuses anonymous callers).
const TEST_API_KEY: &str = "fts-integrity-9128-test-key";
const API_KEY_HEADER: &str = "x-api-key";
/// The documented config location under `$HOME` (`src/config.rs`
/// `LEGACY_CONFIG_DIR` = `.config/ai-memory`, `CONFIG_FILE`), split so the
/// same directory also serves as `XDG_CONFIG_HOME`.
const DOT_CONFIG_DIR: &str = ".config";
const CONFIG_APP_DIR: &str = "ai-memory";
const CONFIG_FILE: &str = "config.toml";
/// The doctor's honest disposition on its read-only connection (#3434):
/// the FTS5 check is a SQLite writer, so the local doctor never runs it and
/// must never claim a verdict for it.
/// The exact value is `src/cli/doctor.rs` `FTS_INTEGRITY_READ_ONLY`.
const DOCTOR_FTS_READ_ONLY: &str =
    "not_observed (read-only; FTS integrity-check is a SQLite writer)";
const DOCTOR_FTS_VERIFIED_PREFIX: &str = "verified";
const DOCTOR_FTS_FACT: &str = "fts_index_integrity";
const DOCTOR_INDEX_SECTION: &str = "Index";
const DOCTOR_SEVERITY_INFO: &str = "info";

/// The ways the derived FTS state can disagree with the rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    /// Control: nothing damaged; every surface must reach `ok`.
    Clean,
    /// A live memory's postings are removed (the audit's `missing` arm).
    MissingLiveRow,
    /// A memory is erased while its postings stay in the index.
    ErasedRowPostings,
    /// A posting for a rowid that no `memories` row has ever owned.
    GhostRowid,
    /// A memory is edited without the index following (row counts equal).
    StalePostings,
}

const DRIFT_ARMS: [Arm; 4] = [
    Arm::MissingLiveRow,
    Arm::ErasedRowPostings,
    Arm::GhostRowid,
    Arm::StalePostings,
];

fn memory(i: usize) -> Memory {
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: format!("drift arm row {i}"),
        content: format!("armtoken{i} originalalpha"),
        namespace: "fts-9128".into(),
        tier: Tier::Long,
        created_at: "2026-01-01T00:00:00+00:00".into(),
        updated_at: "2026-01-01T00:00:00+00:00".into(),
        ..Memory::default()
    }
}

/// Seed [`ARM_ROWS`] rows and return their ids.
fn seed(conn: &rusqlite::Connection) -> Vec<String> {
    (0..ARM_ROWS)
        .map(|i| {
            let m = memory(i);
            db::insert(conn, &m).expect("seed insert");
            m.id
        })
        .collect()
}

/// Re-run `body` with the named sync trigger dropped, then restore it, so the
/// index silently stops following one statement.
fn without_trigger(conn: &rusqlite::Connection, trigger: &str, body: impl FnOnce()) {
    let sql: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
            [trigger],
            |r| r.get(0),
        )
        .expect("trigger sql");
    conn.execute_batch(&format!("DROP TRIGGER {trigger}"))
        .expect("drop trigger");
    body();
    conn.execute_batch(&sql).expect("restore trigger");
}

/// Damage the index as `arm` names. Durable rows are only touched where the
/// arm is about a row change the index did not follow.
fn damage(conn: &rusqlite::Connection, ids: &[String], arm: Arm) {
    let id = &ids[DAMAGED_ROW];
    match arm {
        Arm::Clean => {}
        Arm::MissingLiveRow => {
            conn.execute(
                "INSERT INTO memories_fts(memories_fts, rowid, title, content, tags) \
                 SELECT 'delete', rowid, title, content, tags FROM memories WHERE id=?1",
                [id],
            )
            .expect("fts delete");
        }
        Arm::ErasedRowPostings => without_trigger(conn, "memories_ad", || {
            conn.execute("DELETE FROM memories WHERE id=?1", [id])
                .expect("erase row");
        }),
        Arm::GhostRowid => {
            conn.execute(
                "INSERT INTO memories_fts(rowid, title, content, tags) \
                 VALUES (?1, 'ghost', 'ghostbody', '[]')",
                [GHOST_ROWID],
            )
            .expect("ghost posting");
        }
        Arm::StalePostings => without_trigger(conn, "memories_au", || {
            conn.execute(
                "UPDATE memories SET content='replacementbeta' WHERE id=?1",
                [id],
            )
            .expect("edit row");
        }),
    }
}

/// Assert the deep check failed with exactly the FTS5 content-mismatch error:
/// `SQLITE_CORRUPT_VTAB`, which the worker classifies as [`Outcome::Corrupt`].
/// Any other failure (a lock, a missing table, a closed connection) is a
/// different finding and must not pass as this one.
fn assert_corrupt_vtab(result: anyhow::Result<()>, ctx: &str) {
    let err = match result {
        Ok(()) => panic!("{ctx}: the deep check returned ok over a drifted index"),
        Err(e) => e,
    };
    let extended = match err.downcast_ref::<rusqlite::Error>() {
        Some(rusqlite::Error::SqliteFailure(e, _)) => Some(e.extended_code),
        _ => None,
    };
    assert_eq!(
        (extended, classify_error(&err)),
        (Some(rusqlite::ffi::SQLITE_CORRUPT_VTAB), Outcome::Corrupt),
        "{ctx}: want SQLITE_CORRUPT_VTAB classified Corrupt; got {err:#}"
    );
}

// ---------------------------------------------------------------------------
// The original #4036 regression test (commit d228eb6c9), re-landed.
// ---------------------------------------------------------------------------

#[test]
fn deep_fts_check_detects_equal_count_stale_postings_4036() {
    let conn = db::open(Path::new(":memory:")).unwrap();
    let mem = memory(0);
    db::insert(&conn, &mem).unwrap();
    let status = IntegrityStatus::new(3600);
    assert_eq!(run_once(&conn, &status, 1), Outcome::Verified);
    let trigger: String = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='memories_au'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    conn.execute_batch("DROP TRIGGER memories_au").unwrap();
    conn.execute(
        "UPDATE memories SET content='replacementbeta' WHERE id=?1",
        [&mem.id],
    )
    .unwrap();
    conn.execute_batch(&trigger).unwrap();
    let matches = |token| {
        conn.query_row(
            "SELECT count(*) FROM memories_fts WHERE memories_fts MATCH ?1",
            [token],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
    };
    assert_eq!(matches("originalalpha"), 1);
    assert_eq!(matches("replacementbeta"), 0);
    let counts: (i64, i64) = conn
        .query_row(
            "SELECT (SELECT count(*) FROM memories), (SELECT count(*) FROM memories_fts)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 1));
    assert!(db::fts_probe(&conn).is_ok());
    assert_corrupt_vtab(
        db::fts_integrity_check(&conn),
        "#4036: deep check must compare external content",
    );
    assert_eq!(run_once(&conn, &status, 2), Outcome::Corrupt);
    conn.execute_batch("INSERT INTO memories_fts(memories_fts) VALUES('rebuild')")
        .unwrap();
    assert_eq!(run_once(&conn, &status, 3), Outcome::Verified);
    assert_eq!(matches("originalalpha"), 0);
    assert_eq!(matches("replacementbeta"), 1);
    conn.execute_batch("DROP TABLE memories_fts").unwrap();
    assert_eq!(run_once(&conn, &status, 4), Outcome::Unavailable);
}

// ---------------------------------------------------------------------------
// Invariant 1 + 2, in-process funnel: every drift arm is a confirmed failure.
// ---------------------------------------------------------------------------

#[test]
fn every_drift_arm_fails_the_deep_check_and_the_verdict_funnel_9128() {
    for arm in std::iter::once(Arm::Clean).chain(DRIFT_ARMS) {
        let conn = db::open(Path::new(":memory:")).expect("open");
        let ids = seed(&conn);
        damage(&conn, &ids, arm);
        // The shallow probe /health runs per request cannot see any arm.
        assert!(db::fts_probe(&conn).is_ok(), "{arm:?}: shallow probe");
        // The funnel's own error is the exact content-mismatch code on every
        // drift arm, not merely some failure.
        if arm == Arm::Clean {
            assert!(
                db::fts_integrity_check(&conn).is_ok(),
                "{arm:?}: a clean corpus must verify"
            );
        } else {
            assert_corrupt_vtab(
                db::fts_integrity_check(&conn),
                &format!("#9128 {arm:?}: deep check funnel"),
            );
        }

        let status = IntegrityStatus::new(3_600);
        let outcome = run_once(&conn, &status, 10);
        let verdict = status.verdict_at(10);
        let code = ai_memory::handlers::health_status_code(true, verdict);
        let want = if arm == Arm::Clean {
            (Outcome::Verified, Verdict::Ok, HTTP_OK)
        } else {
            (Outcome::Corrupt, Verdict::Failed, HTTP_UNAVAILABLE)
        };
        assert_eq!(
            (outcome, verdict, code.as_u16()),
            want,
            "#9128 {arm:?}: the deep check must compare postings with the memories rows"
        );
    }
}

// ---------------------------------------------------------------------------
// Invariant 4: a repair is re-verified before the verdict returns to ok.
// ---------------------------------------------------------------------------

#[test]
fn a_repaired_index_returns_to_ok_only_through_a_fresh_check_9128() {
    for arm in DRIFT_ARMS {
        let conn = db::open(Path::new(":memory:")).expect("open");
        let ids = seed(&conn);
        let status = IntegrityStatus::new(3_600);
        damage(&conn, &ids, arm);
        assert_eq!(run_once(&conn, &status, 10), Outcome::Corrupt, "{arm:?}");
        conn.execute_batch("INSERT INTO memories_fts(memories_fts) VALUES('rebuild')")
            .expect("rebuild");
        assert_eq!(
            status.verdict_at(11),
            Verdict::Failed,
            "{arm:?}: a repair alone must not clear the failure"
        );
        assert_eq!(run_once(&conn, &status, 12), Outcome::Verified, "{arm:?}");
        assert_eq!(status.verdict_at(12), Verdict::Ok, "{arm:?}");
    }
}

// ---------------------------------------------------------------------------
// Invariant 3: the deep check's cost is bounded at 100K rows.
// ---------------------------------------------------------------------------

fn seed_bulk(conn: &rusqlite::Connection, n: usize) {
    conn.execute_batch("BEGIN").expect("begin");
    let now = chrono::Utc::now().to_rfc3339();
    let mut stmt = conn
        .prepare(
            "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
             confidence, source, access_count, created_at, updated_at, metadata) \
             VALUES (?1, 'long', 'bound', ?2, ?3, '[]', 5, 1.0, 'api', 0, ?4, ?4, '{}')",
        )
        .expect("prepare seed");
    for i in 0..n {
        stmt.execute(rusqlite::params![
            uuid::Uuid::new_v4().to_string(),
            format!("bound row {i}"),
            format!(
                "corpus filler {i} lorem ipsum dolor sit amet consectetur adipiscing elit \
                 sed do eiusmod tempor incididunt ut labore token{i}"
            ),
            now
        ])
        .expect("seed row");
    }
    drop(stmt);
    conn.execute_batch("COMMIT").expect("commit");
}

#[test]
fn the_deep_check_over_100k_rows_stays_inside_the_writer_bound_9128() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bound.db");
    let conn = db::open(&path).expect("open");
    seed_bulk(&conn, BOUND_ROWS);
    let status = IntegrityStatus::new(3_600);

    let started = Instant::now();
    let outcome = run_once(&conn, &status, 10);
    let took = started.elapsed();
    assert_eq!(outcome, Outcome::Verified);
    assert!(
        took < WRITER_BLOCK_BOUND,
        "#9128: the deep check over {BOUND_ROWS} rows held the writer lock for {took:?}, \
         over the {WRITER_BLOCK_BOUND:?} writer busy_timeout"
    );

    // The bound cell is only meaningful if the comparing form ran: a damaged
    // copy of the same corpus must fail.
    damage(
        &conn,
        &[conn
            .query_row("SELECT id FROM memories LIMIT 1", [], |r| r.get(0))
            .expect("one id")],
        Arm::MissingLiveRow,
    );
    assert_eq!(run_once(&conn, &status, 11), Outcome::Corrupt);
}

// ---------------------------------------------------------------------------
// Transports: HTTP /health, HTTP /monitoring/status, CLI doctor.
// ---------------------------------------------------------------------------

/// Build a damaged database file for `arm` under `dir`.
fn damaged_db(dir: &Path, arm: Arm) -> std::path::PathBuf {
    let path = dir.join(format!("{arm:?}.db"));
    let conn = db::open(&path).expect("open");
    let ids = seed(&conn);
    damage(&conn, &ids, arm);
    drop(conn);
    path
}

#[test]
fn http_health_and_status_turn_not_ok_on_every_drift_arm_9128() {
    let dir = tempfile::tempdir().expect("tempdir");
    for arm in std::iter::once(Arm::Clean).chain(DRIFT_ARMS) {
        let path = damaged_db(dir.path(), arm);
        let mut d = Daemon::start_on(&path);
        let (code, body) = d.first_completed_verdict();
        let v: serde_json::Value = serde_json::from_str(&body).expect("health json");
        let fts = v["fts_integrity"]["status"].as_str();
        if arm == Arm::Clean {
            assert_eq!((code, fts), (HTTP_OK, Some(WIRE_OK)), "{arm:?}: {body}");
            // The control proves the harness is authenticated on every
            // platform: the status route answers 200 with a verified index.
            let (status_code, status_body) = d.get(ROUTE_STATUS);
            let s: serde_json::Value = serde_json::from_str(&status_body).expect("status json");
            assert_eq!(
                (
                    status_code,
                    s["singleton"]["fts_integrity"]["state"].as_str()
                ),
                (HTTP_OK, Some(WIRE_OK)),
                "{arm:?}: {ROUTE_STATUS} body: {status_body}"
            );
            continue;
        }
        assert_eq!(
            (code, v["status"].as_str(), fts),
            (HTTP_UNAVAILABLE, Some(WIRE_ERROR), Some(WIRE_FAILED)),
            "#9128 {arm:?}: /health must not answer ok over a drifted index; body: {body}"
        );

        // The status code first, exactly: an authentication refusal (401 /
        // 403) reports as itself, never as a missing reason in a body that is
        // not a status document. A failed verdict makes the route 503
        // (`src/handlers/monitoring.rs` `failing`).
        let (status_code, status_body) = d.get(ROUTE_STATUS);
        assert_eq!(
            status_code, HTTP_UNAVAILABLE,
            "#9128 {arm:?}: {ROUTE_STATUS} must accept the configured key and answer 503 \
             over a drifted index; body: {status_body}"
        );
        let s: serde_json::Value = serde_json::from_str(&status_body).expect("status json");
        let reasons: Vec<&str> = s["reasons"]
            .as_array()
            .map(|a| a.iter().filter_map(serde_json::Value::as_str).collect())
            .unwrap_or_default();
        assert!(
            reasons.contains(&REASON_INDEX_FAILED),
            "#9128 {arm:?}: monitoring status must name the failed index; body: {status_body}"
        );
        assert_eq!(
            s["singleton"]["fts_integrity"]["state"].as_str(),
            Some(WIRE_FAILED),
            "#9128 {arm:?}: body: {status_body}"
        );
    }
}

/// The CLI doctor opens the database read-only (#3434), and the FTS5 check
/// is a SQLite writer, so the doctor cannot run it. Its invariant for this
/// class is that it never certifies an index it did not compare: over every
/// drift arm the `fts_index_integrity` fact is the explicit `not_observed`
/// disposition, never `verified`.
///
/// Pinned exactly, per arm: the fact is the read-only disposition, the Index
/// section severity is `info` (the FTS fact never raises it), and the exit
/// status and overall severity equal the clean control's, so the read-only
/// doctor neither certifies nor alarms on a check it did not run.
#[test]
fn cli_doctor_never_certifies_a_drifted_index_it_did_not_compare_9128() {
    let dir = tempfile::tempdir().expect("tempdir");
    let control = DoctorRun::on(&damaged_db(dir.path(), Arm::Clean));
    assert!(
        control.exit.is_some(),
        "Clean: doctor must exit with a status, not a signal; stdout: {}",
        control.json
    );
    let drift_runs = DRIFT_ARMS.map(|arm| (arm, DoctorRun::on(&damaged_db(dir.path(), arm))));
    for (arm, run) in std::iter::once((Arm::Clean, &control))
        .chain(drift_runs.iter().map(|(arm, run)| (*arm, run)))
    {
        let fact = find_fact(&run.json, DOCTOR_FTS_FACT).unwrap_or_default();
        assert!(
            !fact.starts_with(DOCTOR_FTS_VERIFIED_PREFIX),
            "#9128 {arm:?}: doctor must not certify an uncompared index; {fact:?}"
        );
        assert_eq!(
            (
                fact.as_str(),
                run.index_severity(),
                run.exit,
                run.json["overall"].as_str()
            ),
            (
                DOCTOR_FTS_READ_ONLY,
                Some(DOCTOR_SEVERITY_INFO),
                control.exit,
                control.json["overall"].as_str()
            ),
            "#9128 {arm:?}: read-only doctor disposition, Index severity, exit status, overall"
        );
    }
}

/// One `ai-memory doctor --json` run: exit status and parsed report.
struct DoctorRun {
    exit: Option<i32>,
    json: serde_json::Value,
}

impl DoctorRun {
    fn on(path: &Path) -> Self {
        let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .args(["--db", &path.display().to_string(), "doctor", "--json"])
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_INFERENCE_EGRESS", "deny")
            .env("AI_MEMORY_EMBED_OFFLINE", "1")
            .env("HF_HUB_OFFLINE", "1")
            .stdin(Stdio::null())
            .output()
            .expect("run doctor");
        let stdout = String::from_utf8_lossy(&out.stdout);
        Self {
            exit: out.status.code(),
            json: serde_json::from_str(&stdout).expect("doctor json"),
        }
    }

    fn index_severity(&self) -> Option<&str> {
        self.json["sections"]
            .as_array()?
            .iter()
            .find(|s| s["name"].as_str() == Some(DOCTOR_INDEX_SECTION))?["severity"]
            .as_str()
    }
}

/// Find the first string value of `key` anywhere in a doctor JSON report
/// (facts are rendered either as objects or as `[key, value]` pairs).
fn find_fact(v: &serde_json::Value, key: &str) -> Option<String> {
    match v {
        serde_json::Value::Object(m) => {
            if let Some(s) = m.get(key).and_then(serde_json::Value::as_str) {
                return Some(s.to_string());
            }
            m.values().find_map(|x| find_fact(x, key))
        }
        serde_json::Value::Array(a) => {
            if let [serde_json::Value::String(k), serde_json::Value::String(val)] = a.as_slice()
                && k == key
            {
                return Some(val.clone());
            }
            a.iter().find_map(|x| find_fact(x, key))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL: the full-text index is a stored generated tsvector with a GIN
// index, maintained by the server in the same transaction as the row, so the
// background checker does not run there. The invariant on this backend is
// that no surface claims a check it never ran: the verdict is `disabled`,
// never `ok`.
// ---------------------------------------------------------------------------

#[cfg(feature = "sal-postgres")]
#[test]
fn postgres_health_never_claims_an_fts_check_it_did_not_run_9128() {
    let Ok(url) = std::env::var("AI_MEMORY_TEST_POSTGRES_URL") else {
        eprintln!("skip: AI_MEMORY_TEST_POSTGRES_URL unset");
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let mut d = Daemon::start_with(&dir.path().join("pg"), None, Some(&url));
    let (code, body) = d.first_completed_verdict();
    let v: serde_json::Value = serde_json::from_str(&body).expect("health json");
    assert_eq!(
        (code, v["fts_integrity"]["status"].as_str()),
        (HTTP_OK, Some(WIRE_DISABLED)),
        "#9128 postgres: /health must not report an FTS verdict it never computed; body: {body}"
    );
}

struct Daemon {
    child: Child,
    port: u16,
    stderr_log: std::path::PathBuf,
}

impl Daemon {
    fn start_on(db_path: &Path) -> Self {
        Self::start_with(db_path, Some(db_path), None)
    }

    /// Spawn `serve` on a SQLite file (`db`) or on a store URL passed through
    /// the environment channel, so a connection URL never reaches argv.
    fn start_with(log_stem: &Path, db: Option<&Path>, store_url: Option<&str>) -> Self {
        let port = free_port();
        let tls = common::tls::shared(&std::env::temp_dir());
        let stderr_log = log_stem.with_extension("serve-stderr.log");
        let stderr_file = std::fs::File::create(&stderr_log).expect("stderr log");
        // A per-daemon HOME carrying only the keyword tier and the test key:
        // the serve key is read from config, never from argv. The file sits at
        // `$HOME/.config/ai-memory/config.toml` with `XDG_CONFIG_HOME` set to
        // `$HOME/.config`, the one path the config resolver reads on every
        // platform: the XDG path on Linux, the documented dot-config path on
        // macOS, where `dirs::config_dir()` ignores `XDG_CONFIG_HOME`
        // (`src/config.rs` `resolve_config_path_choice`; precedent
        // `tests/bind_api_key_token_file_3781.rs`).
        let home = log_stem.with_extension("home");
        let config_home = home.join(DOT_CONFIG_DIR);
        let config_dir = config_home.join(CONFIG_APP_DIR);
        std::fs::create_dir_all(&config_dir).expect("config dir");
        std::fs::write(
            config_dir.join(CONFIG_FILE),
            format!("tier = \"keyword\"\napi_key = \"{TEST_API_KEY}\"\n"),
        )
        .expect("write config");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
        cmd.args(["serve", "--host", "127.0.0.1", "--port", &port.to_string()]);
        if let Some(db) = db {
            cmd.args(["--db", &db.display().to_string()]);
        }
        if let Some(url) = store_url {
            cmd.env("AI_MEMORY_STORE_URL", url);
        }
        let child = cmd
            .args(tls.serve_arg_strs())
            .env_remove("AI_MEMORY_NO_CONFIG")
            .env("XDG_CONFIG_HOME", &config_home)
            .env("HOME", &home)
            .env("AI_MEMORY_INFERENCE_EGRESS", "deny")
            .env("AI_MEMORY_EMBED_OFFLINE", "1")
            .env("HF_HUB_OFFLINE", "1")
            .env("AI_MEMORY_BOOT_ENABLED", "0")
            .env("AI_MEMORY_FTS_INTEGRITY_INTERVAL_SECS", CHECK_INTERVAL_SECS)
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .expect("spawn ai-memory serve");
        Self {
            child,
            port,
            stderr_log,
        }
    }

    /// Wait until `/health` publishes a COMPLETED verdict (anything but
    /// `pending`), then return that response. Ordered on the observable
    /// verdict, not on elapsed time; the deadline is only a hang guard.
    fn first_completed_verdict(&mut self) -> (u16, String) {
        let deadline = Instant::now() + VERDICT_HANG_GUARD;
        while Instant::now() < deadline {
            if let Some((code, body)) = self.try_get(ROUTE_HEALTH) {
                let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
                if v["fts_integrity"]["status"].as_str() != Some(WIRE_PENDING) {
                    return (code, body);
                }
            }
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                panic!(
                    "daemon exited ({status}); stderr:\n{}",
                    String::from_utf8_lossy(&std::fs::read(&self.stderr_log).unwrap_or_default())
                );
            }
            std::thread::sleep(POLL_STEP);
        }
        panic!("daemon on port {} never completed a check", self.port);
    }

    fn get(&self, path: &str) -> (u16, String) {
        self.try_get(path)
            .unwrap_or_else(|| panic!("GET {path} failed on port {}", self.port))
    }

    fn try_get(&self, path: &str) -> Option<(u16, String)> {
        let tls = common::tls::shared(&std::env::temp_dir());
        let resp = tls
            .client_with_timeout(Duration::from_secs(30))
            .get(format!(
                "{}{path}",
                common::tls::TestTls::base_url(self.port)
            ))
            .header(API_KEY_HEADER, TEST_API_KEY)
            .send()
            .ok()?;
        let status = resp.status().as_u16();
        let body = resp.text().ok()?;
        Some((status, body))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().expect("addr").port()
}
