// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 [#2579](https://github.com/alphaonedev/ai-memory-mcp/issues/2579) +
//! [#2583](https://github.com/alphaonedev/ai-memory-mcp/issues/2583) — the two
//! observability endpoints must cost O(1), not O(corpus).
//!
//! **R-203 fail-at-parent.** Cells A-E reference NO symbol introduced by the
//! fix, so this file compiles unchanged at the parent commit and FAILS there:
//!
//! | cell | at parent |
//! |---|---|
//! | A | `db::health_check` executes `INSERT INTO memories_fts(memories_fts) VALUES('integrity-check')` |
//! | B | that statement is O(corpus): ~110 ms at 5k rows vs a <20 ms budget |
//! | C | `/health` renders no `checks` / `fts_integrity` block, so it cannot say what it verified |
//! | D | `/metrics` exposes no `ai_memory_memories_refreshed_at_seconds`, so a frozen gauge is undetectable |
//! | E | `/metrics` recomputes per scrape, so there is no refresh stamp to hold still |
//!
//! Cell H is the CONTROL that keeps the refusal cells from passing for a
//! trivial reason — the [#2449](https://github.com/alphaonedev/ai-memory-mcp/issues/2449)
//! harness lesson that a daemon which never started "passes" every assertion
//! about what it did not do. It too references only pre-existing symbols, so
//! the WHOLE file compiles at the parent commit; a file that failed to COMPILE
//! there would prove nothing about behaviour.
//!
//! The companion contract pins — what `/health` STILL guarantees — live in
//! `tests/health_fts_verdict_contract_2579.rs`, deliberately split out because
//! they reference the new surface and would otherwise break this file's
//! compile-at-parent property.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ai_memory::db;

// ---------------------------------------------------------------------------
// The statement fragments the two endpoints must NOT execute.
// ---------------------------------------------------------------------------

/// The FTS5 external-content integrity-check command. It re-tokenizes every
/// row of `memories` and compares the derived doclists, and `SQLite` prepares
/// it as a WRITER, so it takes the WAL write lock for its whole duration.
const FTS_INTEGRITY_COMMAND: &str = "integrity-check";

/// The `db::stats` field that dominates its cost: it walks every row's
/// `embedding` BLOB. `/metrics` used one field of `stats` and paid for all of
/// them.
const DIM_VIOLATION_FRAGMENT: &str = "length(embedding)";

/// A full count over the CONTENT table. The old probe issued this alongside
/// the integrity check; a liveness probe must never scan the corpus.
const CONTENT_TABLE_COUNT: &str = "COUNT(*) FROM memories";

/// Rows seeded for the scaling cells. Large enough that an O(corpus) probe is
/// unmistakable (~110 ms at the measured 22 us/row), small enough to seed in a
/// second.
const SCALING_ROWS: usize = 5_000;

/// Wall-clock budget for a liveness probe over `SCALING_ROWS` rows. The fixed
/// path measures well under 1 ms; 20 ms is a ~20x margin over the fixed cost
/// and a ~5x margin under the parent's O(corpus) cost, so the cell is neither
/// flaky nor vacuous.
const PROBE_BUDGET: Duration = Duration::from_millis(20);

// ---------------------------------------------------------------------------
// SQL-trace capture (rusqlite `trace` feature, a dev-dependency).
// ---------------------------------------------------------------------------

static TRACE_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn record_statement(sql: &str) {
    if let Ok(mut g) = TRACE_LOG.lock() {
        g.push(sql.to_string());
    }
}

fn take_trace() -> Vec<String> {
    TRACE_LOG
        .lock()
        .map(|mut g| std::mem::take(&mut *g))
        .unwrap_or_default()
}

fn seed_rows(conn: &rusqlite::Connection, n: usize) {
    conn.execute_batch("BEGIN").expect("begin");
    let now = chrono::Utc::now().to_rfc3339();
    let mut stmt = conn
        .prepare(
            "INSERT INTO memories (id, tier, namespace, title, content, tags, priority, \
             confidence, source, access_count, created_at, updated_at, metadata) \
             VALUES (?1, 'long', 'perf', ?2, ?3, '[]', 5, 1.0, 'api', 0, ?4, ?4, '{}')",
        )
        .expect("prepare seed");
    for i in 0..n {
        let title = format!("probe row {i}");
        let content = format!(
            "corpus filler {i} lorem ipsum dolor sit amet consectetur adipiscing elit sed do \
             eiusmod tempor incididunt ut labore et dolore magna aliqua token{i}"
        );
        stmt.execute(rusqlite::params![
            uuid::Uuid::new_v4().to_string(),
            title,
            content,
            now
        ])
        .expect("seed row");
    }
    drop(stmt);
    conn.execute_batch("COMMIT").expect("commit");
}

// ---------------------------------------------------------------------------
// CELL A (fail-at-parent) — the liveness probe issues no O(corpus) statement.
// ---------------------------------------------------------------------------

#[test]
fn a_health_check_executes_no_fts_integrity_check() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut conn = db::open(&dir.path().join("a.db")).expect("open");
    seed_rows(&conn, 64);

    let _ = take_trace();
    conn.trace(Some(record_statement));
    let ok = db::health_check(&conn).expect("health_check");
    conn.trace(None);
    assert!(ok, "the probe must still report the connection usable");

    let stmts = take_trace();
    assert!(
        !stmts.is_empty(),
        "the trace hook captured nothing — the cell would pass vacuously"
    );

    // The load-bearing refusals, over EVERY traced statement including the
    // ones SQLite expands internally.
    for sql in &stmts {
        assert!(
            !sql.contains(FTS_INTEGRITY_COMMAND),
            "the liveness probe ran the O(corpus) FTS5 integrity check: {sql}"
        );
        assert!(
            !sql.contains(CONTENT_TABLE_COUNT),
            "the liveness probe counted the whole content table: {sql}"
        );
    }

    // Exactly two statements are issued BY the probe; everything else in the
    // trace is SQLite's own expansion of the MATCH (prefixed `-- `).
    let issued: Vec<&String> = stmts
        .iter()
        .filter(|s| !s.trim_start().starts_with("--"))
        .collect();
    assert_eq!(
        issued.len(),
        2,
        "a liveness probe must issue a FIXED statement set; got {issued:?}"
    );

    // Anti-vacuity: the FTS reachability probe must actually have run, not
    // been silently skipped — otherwise "no integrity check" is trivially true.
    assert!(
        issued.iter().any(|s| s.contains("memories_fts")),
        "the FTS5 reachability probe did not run: {issued:?}"
    );

    // The SHAPE proof, and it is load-independent — this is what makes the
    // probe O(1) in ROWS. SQLite expands the MATCH into one lookup per FTS5
    // SEGMENT against `memories_fts_idx`, each an indexed `term <= ?` seek
    // with `LIMIT 1`. Segment count is bounded by FTS5's own merge policy
    // (it grows ~logarithmically and is capped, never linearly in rows), and
    // no expansion touches the `memories` content table at all — which is
    // precisely what the integrity-check DID, and why that one was O(corpus).
    let seeks: Vec<&String> = stmts
        .iter()
        .filter(|s| s.contains("memories_fts_idx"))
        .collect();
    assert!(
        !seeks.is_empty(),
        "expected the MATCH to expand into segment-index seeks: {stmts:?}"
    );
    for sql in &seeks {
        assert!(
            sql.contains("LIMIT 1"),
            "an unbounded segment scan would re-introduce corpus-proportional cost: {sql}"
        );
    }
}

// ---------------------------------------------------------------------------
// CELL B (fail-at-parent) — the probe's cost does not scale with the corpus.
// ---------------------------------------------------------------------------

#[test]
fn b_health_check_cost_is_flat_across_corpus_sizes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let conn = db::open(&dir.path().join("b.db")).expect("open");

    // Warm every code path first so neither sample pays a one-off.
    for _ in 0..5 {
        db::health_check(&conn).expect("warm");
    }
    let empty = best_of(8, || {
        db::health_check(&conn).expect("probe empty");
    });

    seed_rows(&conn, SCALING_ROWS);
    for _ in 0..5 {
        db::health_check(&conn).expect("warm");
    }
    let populated = best_of(8, || {
        db::health_check(&conn).expect("probe populated");
    });

    assert!(
        populated < PROBE_BUDGET,
        "liveness probe took {populated:?} at {SCALING_ROWS} rows (budget {PROBE_BUDGET:?}) — \
         the O(corpus) shape is back"
    );
    // The absolute budget is the load-bearing assertion; the ratio is the
    // diagnostic. An empty-corpus probe is sub-microsecond, so a ratio bound
    // alone would be noise-dominated.
    assert!(
        empty < PROBE_BUDGET,
        "even the empty-corpus probe exceeded the budget ({empty:?}) — the host is too loaded \
         for this cell to mean anything"
    );
}

fn best_of(n: usize, mut f: impl FnMut()) -> Duration {
    let mut best = Duration::from_secs(u64::from(u32::MAX));
    for _ in 0..n {
        let t = Instant::now();
        f();
        best = best.min(t.elapsed());
    }
    best
}

// ---------------------------------------------------------------------------
// CELL C (fail-at-parent) — /health says what it actually verified.
// ---------------------------------------------------------------------------

#[test]
fn c_health_body_declares_what_it_checked() {
    let d = Daemon::start(0);
    let (status, body) = d.get("/api/v1/health");
    assert_eq!(status, 200, "body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("health json");

    let checks = v
        .get("checks")
        .unwrap_or_else(|| panic!("/health must declare WHAT it checked; body: {body}"));
    assert_eq!(
        checks.get("connection").and_then(serde_json::Value::as_str),
        Some("ok"),
        "body: {body}"
    );
    assert!(
        checks.get("fts_index").is_some(),
        "/health must name its FTS probe so a shallow pass is never read as a deep one; \
         body: {body}"
    );

    let fts = v
        .get("fts_integrity")
        .unwrap_or_else(|| panic!("/health must surface the cached deep verdict; body: {body}"));
    let status_tag = fts.get("status").and_then(serde_json::Value::as_str);
    assert!(
        matches!(
            status_tag,
            Some("pending" | "ok" | "stale" | "failed" | "disabled")
        ),
        "unexpected fts_integrity.status {status_tag:?}; body: {body}"
    );
    assert!(
        fts.get("checked_at").is_some(),
        "the verdict's AGE must be visible, never implied; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// CELL D (fail-at-parent) — the corpus gauge publishes its own freshness.
// ---------------------------------------------------------------------------

#[test]
fn d_metrics_publishes_a_gauge_freshness_stamp() {
    let d = Daemon::start(0);
    let (status, body) = d.get("/metrics");
    assert_eq!(status, 200);
    assert!(
        body.contains("ai_memory_memories_refreshed_at_seconds"),
        "a pre-computed gauge with no freshness stamp is indistinguishable from a frozen one \
         (#2444); body:\n{body}"
    );
    assert!(body.contains("ai_memory_memories"), "body:\n{body}");
}

// ---------------------------------------------------------------------------
// CELL E (fail-at-parent) — the scrape path recomputes nothing.
// ---------------------------------------------------------------------------

#[test]
fn e_repeated_scrapes_do_not_recompute_the_corpus_count() {
    let d = Daemon::start(0);
    let first = scrape_refresh_stamp(&d);
    for _ in 0..12 {
        let _ = d.get("/metrics");
    }
    let last = scrape_refresh_stamp(&d);
    assert_eq!(
        first, last,
        "the refresh stamp moved across 14 back-to-back scrapes — the scrape path is still \
         doing per-request database work"
    );
}

fn scrape_refresh_stamp(d: &Daemon) -> String {
    let (_, body) = d.get("/metrics");
    body.lines()
        .find(|l| l.starts_with("ai_memory_memories_refreshed_at_seconds "))
        .unwrap_or_else(|| panic!("no refresh stamp in:\n{body}"))
        .to_string()
}

// ---------------------------------------------------------------------------
// CELL H (CONTROL) — the daemon really serves, so the cells above are not
// passing because nothing ever ran.
// ---------------------------------------------------------------------------

#[test]
fn h_control_daemon_serves_a_real_corpus_and_counts_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("control.db");
    {
        let conn = db::open(&path).expect("open");
        seed_rows(&conn, 37);
    }
    let d = Daemon::start_on(&path);
    let (status, body) = d.get("/api/v1/health");
    assert_eq!(status, 200, "control daemon did not serve: {body}");

    let (_, metrics) = d.get("/metrics");
    let line = metrics
        .lines()
        .find(|l| l.starts_with("ai_memory_memories "))
        .unwrap_or_else(|| panic!("no corpus gauge in:\n{metrics}"));
    assert!(
        line.ends_with(" 37"),
        "the pre-computed gauge must carry the REAL corpus size, not a placeholder: {line}"
    );
    assert!(
        !metrics.contains(DIM_VIOLATION_FRAGMENT),
        "sanity: the render must not be echoing SQL"
    );
}

// ---------------------------------------------------------------------------
// Subprocess daemon harness.
// ---------------------------------------------------------------------------

struct Daemon {
    child: Child,
    port: u16,
    dir: Option<tempfile::TempDir>,
}

impl Daemon {
    fn start(seed: usize) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("daemon.db");
        if seed > 0 {
            // Scope the writer so its connection is closed before the daemon
            // opens the same file.
            let conn = db::open(&path).expect("open");
            seed_rows(&conn, seed);
            drop(conn);
        }
        let mut d = Self::start_on(&path);
        d.dir = Some(dir);
        d
    }

    fn start_on(db_path: &Path) -> Self {
        let port = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .args([
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--db",
                &db_path.display().to_string(),
            ])
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_INFERENCE_EGRESS", "deny")
            .env("AI_MEMORY_EMBED_OFFLINE", "1")
            .env("HF_HUB_OFFLINE", "1")
            .env("AI_MEMORY_BOOT_ENABLED", "0")
            .env("RUST_LOG", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ai-memory serve");
        let d = Self {
            child,
            port,
            dir: None,
        };
        d.wait_ready();
        d
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_mins(1);
        while Instant::now() < deadline {
            if let Some((200, _)) = self.try_get("/api/v1/health") {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("daemon on port {} never became ready", self.port);
    }

    fn get(&self, path: &str) -> (u16, String) {
        self.try_get(path)
            .unwrap_or_else(|| panic!("GET {path} failed on port {}", self.port))
    }

    fn try_get(&self, path: &str) -> Option<(u16, String)> {
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(30))).ok()?;
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        .ok()?;
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).ok()?;
        let text = String::from_utf8_lossy(&raw).into_owned();
        let mut lines = BufReader::new(text.as_bytes()).lines();
        let status: u16 = lines
            .next()?
            .ok()?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string())?;
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
