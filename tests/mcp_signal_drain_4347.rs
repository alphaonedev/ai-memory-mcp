// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4347 — `ai-memory mcp` stopped by a signal still drains its forensic
//! writer.
//!
//! #4319 keeps the background forensic writer for `mcp` and drains it at exit
//! (`atexit`). A process that ends by a signal's DEFAULT disposition never
//! runs `atexit`, so a SIGTERM (supervisor stop, `kill`), SIGINT (Ctrl-C) or
//! SIGHUP (terminal hang-up) lost every row still queued. These cells spawn
//! the real binary as an MCP child, make an acknowledged write and a forensic
//! row, slow the background writer so the row is certainly still queued
//! (`AI_MEMORY_TEST_FORENSIC_WRITER_DELAY_MS`), signal the child by pid, and
//! require: the forensic row on disk, one unbroken chain, the acknowledged
//! write durable, and the conventional exit code (128 + signal number).
//!
//! Every wait is bounded: a child that does not exit is killed by pid and the
//! cell fails, it never hangs.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ai_memory::governance::audit::{
    CHAIN_HEAD_PREV_HASH, ForensicDecision, TEST_FORENSIC_WRITER_DELAY_ENV,
};
use serde_json::{Value, json};

/// Writer delay that makes a queued row certainly outlive a signalled process.
const WRITER_DELAY_MS: &str = "600";

/// Steady-state hang guard: how long a child that is already serving may take
/// to exit after a signal before the cell fails. Generous because eleven cells
/// share one loaded host, but still a bound (a hung drain must fail the cell).
const EXIT_BOUND: Duration = Duration::from_secs(60);

/// Start-up limit: how long a freshly spawned debug binary may take to reach
/// its first observable point (initialize response, held request, a stderr
/// line, the start-up refusal exit). Child start-up is scheduler-bound, not
/// product-bound, so it gets its own far larger but still finite limit (#6108
/// F-1/F-6: a fixed 30 s overran on a loaded host and failed the burst cell
/// before it reached the behaviour under test).
const STARTUP_BOUND: Duration = Duration::from_secs(300);

/// Title of the acknowledged write each cell must find durable.
const ACKED_TITLE: &str = "acked-before-signal-4347";

const SIGHUP_CODE: i32 = 129;
const SIGINT_CODE: i32 = 130;
const SIGTERM_CODE: i32 = 143;

fn sandbox() -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("create test scratch root");
    tempfile::tempdir_in(root).expect("isolated test directory")
}

fn forensic_dir(home: &Path) -> PathBuf {
    home.join("audit")
}

fn db_path(home: &Path) -> PathBuf {
    home.join("signal.db")
}

/// An MCP child, isolated: own config (flat trail off, forensic dir here),
/// own key dir, own db, the writer slowed.
fn spawn_mcp(home: &Path, extra_env: &[(&str, String)], ignored: &[libc::c_int]) -> Child {
    let config_root = home.join(".config").join("ai-memory");
    std::fs::create_dir_all(&config_root).expect("create config root");
    std::fs::write(
        config_root.join("config.toml"),
        format!(
            "schema_version = 2\ntier = \"keyword\"\n\n[audit]\nenabled = false\npath = \"{}\"\n",
            forensic_dir(home).display()
        ),
    )
    .expect("write config");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env(
            "AI_MEMORY_KEY_DIR",
            ai_memory::identity::test_key_dir::install(),
        )
        .env(TEST_FORENSIC_WRITER_DELAY_ENV, WRITER_DELAY_MS)
        .current_dir(home)
        .arg("--db")
        .arg(db_path(home))
        .args(["mcp", "--profile", "full"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    // SAFETY: the closure runs between fork and exec and only calls
    // `signal(2)`, which is async-signal-safe. It resets the dispositions the
    // cells signal to SIG_DFL, so a runner started with SIGHUP/SIGINT ignored
    // (nohup, a background job) cannot change which cells are red on a
    // carrier without a handler.
    let ignored = ignored.to_vec();
    unsafe {
        cmd.pre_exec(move || {
            for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                libc::signal(sig, libc::SIG_DFL);
            }
            // #4473 — the cells that pin an inherited ignore set it here.
            for sig in &ignored {
                libc::signal(*sig, libc::SIG_IGN);
            }
            Ok(())
        });
    }
    cmd.spawn().expect("spawn mcp")
}

struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    /// Everything the child wrote to stderr so far (a reader thread fills it).
    stderr_buf: Arc<Mutex<String>>,
    stderr_thread: Option<std::thread::JoinHandle<()>>,
}

impl Session {
    /// Spawn, initialize, make one acknowledged write and one forensic row.
    fn start(home: &Path) -> Self {
        Self::start_with(home, &[])
    }

    fn start_with(home: &Path, extra_env: &[(&str, String)]) -> Self {
        Self::start_full(home, extra_env, &[])
    }

    fn start_full(home: &Path, extra_env: &[(&str, String)], ignored: &[libc::c_int]) -> Self {
        let mut s = Self::attach(spawn_mcp(home, extra_env, ignored));
        s.handshake();
        s
    }

    /// Wrap a spawned child: capture its stderr on a reader thread.
    fn attach(child: Child) -> Self {
        Self::attach_gated(child, Arc::new(AtomicBool::new(true)))
    }

    /// As [`Self::attach`], but the stderr reader thread captures nothing
    /// until `gate` is set. A test holds the gate shut to make "the child has
    /// exited but the reader has not yet appended its last line" a fixed state
    /// instead of a scheduling race (#6142). The pipe buffers the child's
    /// output meanwhile, so nothing is lost.
    fn attach_gated(mut child: Child, gate: Arc<AtomicBool>) -> Self {
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let stderr_buf = Arc::new(Mutex::new(String::new()));
        let mut child_stderr = child.stderr.take().expect("stderr");
        let sink = Arc::clone(&stderr_buf);
        let stderr_thread = std::thread::spawn(move || {
            while !gate.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(5));
            }
            let mut chunk = [0_u8; 1024];
            while let Ok(n) = child_stderr.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if let Ok(mut buf) = sink.lock() {
                    buf.push_str(&String::from_utf8_lossy(&chunk[..n]));
                }
            }
        });
        Self {
            child,
            stdin: Some(stdin),
            stdout,
            stderr_buf,
            stderr_thread: Some(stderr_thread),
        }
    }

    /// Initialize, make one acknowledged write and one forensic row.
    fn handshake(&mut self) {
        let s = self;
        let init = s.request(
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2024-11-05","capabilities":{},
            "clientInfo":{"name":"probe4347","version":"1"}}}),
        );
        assert!(init.get("error").is_none(), "initialize: {init}");
        let stored = s.request(
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
            "name":"memory_store","arguments":{
                "title":ACKED_TITLE,"content":"acknowledged before the signal",
                "namespace":"t4347","tier":"long"}}}),
        );
        assert!(stored.get("error").is_none(), "memory_store: {stored}");
        // `memory_delete` records its forensic row before the permission
        // gate, so deleting an id that does not exist still writes one row.
        let _ = s.request(
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
            "name":"memory_delete","arguments":{"id":"00000000-0000-4000-8000-000000004347"}}}),
        );
    }

    /// Send one request line without waiting for its response.
    fn send(&mut self, req: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{req}").expect("write request");
        stdin.flush().expect("flush");
    }

    /// Read one response line (blocks; the cells' children are bounded).
    fn read_response(&mut self) -> Option<Value> {
        let mut line = String::new();
        match self.stdout.read_line(&mut line) {
            Ok(n) if n > 0 => serde_json::from_str(&line).ok(),
            _ => None,
        }
    }

    fn request(&mut self, req: &Value) -> Value {
        let stdin = self.stdin.as_mut().expect("stdin open");
        writeln!(stdin, "{req}").expect("write request");
        stdin.flush().expect("flush");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read response");
        serde_json::from_str(&line).expect("json response")
    }

    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .args(["-s", name, &self.child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -s {name} failed");
    }

    /// Wait for exit, bounded; kill by pid and fail when it does not exit.
    fn wait_bounded(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + EXIT_BOUND;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("mcp did not exit within {EXIT_BOUND:?} of the signal");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// All of the child's stderr (call after it exited: joins the reader).
    fn stderr_text(&mut self) -> String {
        if let Some(t) = self.stderr_thread.take() {
            let _ = t.join();
        }
        self.stderr_buf
            .lock()
            .map(|b| b.clone())
            .unwrap_or_default()
    }

    /// Fail at once, with the exit status and all captured stderr, when the
    /// child has already exited while a start-up wait is still polling: a
    /// child that crashed at start-up must not cost the full `STARTUP_BOUND`
    /// (#4347 L-2, TEST-02).
    ///
    /// The child may have written the awaited line and exited before the
    /// stderr reader thread appended it, so on exit the reader is joined (it
    /// reads to EOF) and `done` is evaluated on the complete stderr. Returns
    /// `true` when the child exited but the awaited condition now holds (the
    /// caller then returns instead of waiting); panics only when it does not
    /// (#6142, TEST-02). Returns `false` while the child is still running.
    fn fail_if_exited(&mut self, waiting_for: &str, done: impl Fn(&str) -> bool) -> bool {
        let Some(status) = self.child.try_wait().expect("try_wait") else {
            return false;
        };
        let stderr = self.stderr_text();
        if done(&stderr) {
            return true;
        }
        panic!("the child exited ({status:?}) while waiting for {waiting_for}; stderr:\n{stderr}");
    }

    /// Wait (bounded) until the child has written `needle` to stderr; fails
    /// fast if the child exits first.
    fn wait_stderr_contains(&mut self, needle: &str) {
        let deadline = Instant::now() + STARTUP_BOUND;
        loop {
            if self.stderr_buf.lock().is_ok_and(|b| b.contains(needle)) {
                return;
            }
            if self.fail_if_exited(&format!("{needle:?} on stderr"), |e| e.contains(needle)) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the child never wrote {needle:?} to stderr"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Wait (bounded) for the child to reach the held point; fails fast if
    /// the child exits first.
    fn wait_entered(&mut self, dir: &Path) {
        let deadline = Instant::now() + STARTUP_BOUND;
        while !dir.join("entered").exists() {
            // The `entered` marker is a file written before the child blocks,
            // so after the child exits its final state is already on disk.
            if self.fail_if_exited("the held request", |_| dir.join("entered").exists()) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the child never reached the held request"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Every parseable forensic row, in file (chain) order.
fn rows(home: &Path) -> Vec<ForensicDecision> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(forensic_dir(home))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().is_some_and(|e| e == "jsonl")
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.starts_with("forensic-"))
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    files
        .iter()
        .flat_map(|p| {
            std::fs::read_to_string(p)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str::<ForensicDecision>(l).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn assert_one_unbroken_chain(recs: &[ForensicDecision]) {
    assert!(!recs.is_empty(), "no forensic rows on disk");
    assert_eq!(
        recs[0].prev_hash, CHAIN_HEAD_PREV_HASH,
        "the chain starts at genesis"
    );
    for pair in recs.windows(2) {
        assert_eq!(
            pair[1].prev_hash,
            pair[0].self_hash(),
            "each row continues the previous one"
        );
    }
}

/// The acknowledged write is durable: it is in the database after exit.
fn assert_acked_write_durable(home: &Path) {
    let conn = rusqlite::Connection::open(db_path(home)).expect("reopen db after exit");
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM memories WHERE title = ?1",
            [ACKED_TITLE],
            |r| r.get(0),
        )
        .expect("count acknowledged row");
    assert_eq!(n, 1, "the write acknowledged before the signal is lost");
}

fn delete_rows(recs: &[ForensicDecision]) -> usize {
    recs.iter().filter(|r| r.kind == "memory_delete").count()
}

/// Signal the session and assert the drain, the chain, the data and the code.
fn signalled_exit_drains(home: &Path, signal: &str, code: i32) {
    let mut s = Session::start(home);
    s.signal(signal);
    let status = s.wait_bounded();
    assert_eq!(
        status.code(),
        Some(code),
        "SIG{signal} must end mcp with exit code {code} (signal-killed: {:?}); stderr: {}",
        std::os::unix::process::ExitStatusExt::signal(&status),
        s.stderr_text()
    );
    let recs = rows(home);
    assert_eq!(
        delete_rows(&recs),
        1,
        "the row queued before SIG{signal} must be on disk; rows: {:?}",
        recs.iter().map(|r| r.kind.clone()).collect::<Vec<_>>()
    );
    assert_one_unbroken_chain(&recs);
    assert_acked_write_durable(home);
}

#[test]
fn sigterm_drains_the_forensic_writer_and_exits_143_4347() {
    let home = sandbox();
    signalled_exit_drains(home.path(), "TERM", SIGTERM_CODE);
}

#[test]
fn sigint_drains_the_forensic_writer_and_exits_130_4347() {
    let home = sandbox();
    signalled_exit_drains(home.path(), "INT", SIGINT_CODE);
}

#[test]
fn sighup_drains_the_forensic_writer_and_exits_129_4347() {
    let home = sandbox();
    signalled_exit_drains(home.path(), "HUP", SIGHUP_CODE);
}

/// A signal racing stdin EOF: both the signal path and the normal-exit path
/// want to drain. The row is written exactly once (one row, unbroken chain),
/// the process exits promptly with either the normal or the signal code, and
/// the stop line is logged at most once.
#[test]
fn a_signal_racing_stdin_eof_drains_exactly_once_4347() {
    for _ in 0..5 {
        let home = sandbox();
        let mut s = Session::start(home.path());
        s.signal("TERM");
        drop(s.stdin.take());
        let status = s.wait_bounded();
        let code = status.code();
        assert!(
            code == Some(0) || code == Some(SIGTERM_CODE),
            "exit code must be normal or 143, got {code:?}"
        );
        let stderr = s.stderr_text();
        assert!(
            stderr.matches("forensic exit drain").count() <= 1,
            "the drain announcement must appear at most once: {stderr}"
        );
        let recs = rows(home.path());
        assert_eq!(delete_rows(&recs), 1, "the row is written exactly once");
        assert_one_unbroken_chain(&recs);
        assert_acked_write_durable(home.path());
    }
}

/// Control: a normal stdin-EOF exit still drains and still exits 0.
#[test]
fn stdin_eof_still_drains_and_exits_zero_4347() {
    let home = sandbox();
    let mut s = Session::start(home.path());
    drop(s.stdin.take());
    let status = s.wait_bounded();
    assert_eq!(status.code(), Some(0), "stderr: {}", s.stderr_text());
    let recs = rows(home.path());
    assert_eq!(delete_rows(&recs), 1);
    assert_one_unbroken_chain(&recs);
    assert_acked_write_durable(home.path());
}

fn count_title(home: &Path, title: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path(home)).expect("reopen db after exit");
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE title = ?1",
        [title],
        |r| r.get(0),
    )
    .expect("count rows")
}

/// A fresh directory for the hold barrier files.
fn barrier_dir(home: &Path) -> PathBuf {
    let dir = home.join("barrier");
    std::fs::create_dir_all(&dir).expect("create barrier dir");
    dir
}

fn hold_env(id: u64, dir: &Path) -> (&'static str, String) {
    (
        "AI_MEMORY_TEST_HOLD_IN_FLIGHT",
        format!("{id}:{}", dir.display()),
    )
}

/// Request id the cells hold in flight.
const HELD_ID: u64 = 7777;
const HELD_TITLE: &str = "held-in-flight-4347";
const AFTER_TITLE: &str = "sent-after-the-signal-4347";

fn store_request(id: u64, title: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
        "name":"memory_store","arguments":{
            "title":title,"content":"in flight","namespace":"t4347","tier":"long"}}})
}

/// B2 — a request IN FLIGHT at the signal: held after it ran and before its
/// ack, signalled mid-request, released inside the budget. It completes, is
/// acknowledged, and is durable; a request sent after the signal is never
/// processed. The `InFlight` claim proves the real loop guard is engaged.
#[test]
fn an_in_flight_request_is_acknowledged_and_durable_after_the_signal_4347() {
    let home = sandbox();
    let dir = barrier_dir(home.path());
    let mut s = Session::start_with(home.path(), &[hold_env(HELD_ID, &dir)]);
    s.send(&store_request(HELD_ID, HELD_TITLE));
    s.wait_entered(&dir);
    s.signal("TERM");
    // Wait for the stop claim, so the line sent next is certainly read after
    // it (event-driven, not a sleep).
    s.wait_stderr_contains("(InFlight)");
    // Sent after the signal: the loop must not process it.
    s.send(&store_request(HELD_ID + 1, AFTER_TITLE));
    std::fs::write(dir.join("release"), b"").expect("release the held request");
    let held = s
        .read_response()
        .expect("the in-flight request is acknowledged");
    assert_eq!(held["id"], json!(HELD_ID), "{held}");
    assert!(held.get("error").is_none(), "{held}");
    let status = s.wait_bounded();
    let stderr = s.stderr_text();
    assert_eq!(status.code(), Some(SIGTERM_CODE), "stderr: {stderr}");
    assert!(
        stderr.contains("(InFlight)"),
        "the stop must have found a request in flight: {stderr}"
    );
    assert_eq!(
        count_title(home.path(), HELD_TITLE),
        1,
        "acknowledged write lost"
    );
    assert_eq!(
        count_title(home.path(), AFTER_TITLE),
        0,
        "a request read after the stop must not be processed"
    );
    assert_one_unbroken_chain(&rows(home.path()));
    assert_acked_write_durable(home.path());
}

/// F2 — a request still running when its budget expires is never
/// acknowledged, and the drain still covers its forensic row. Held after the
/// `memory_delete` ran (its row is queued) and never released before the
/// stop: the in-flight budget is shortened by the debug seam.
///
/// This cell pins the budget expiry only; the fence end to end (a request
/// released after the fence while the drain runs) is pinned by
/// `a_fenced_request_released_mid_drain_is_never_acknowledged_4347`.
#[test]
fn a_request_past_its_budget_is_never_acknowledged_and_keeps_its_row_4347() {
    let home = sandbox();
    let dir = barrier_dir(home.path());
    let mut s = Session::start_with(
        home.path(),
        &[
            hold_env(HELD_ID, &dir),
            ("AI_MEMORY_TEST_IN_FLIGHT_BUDGET_MS", "300".to_string()),
        ],
    );
    s.send(
        &json!({"jsonrpc":"2.0","id":HELD_ID,"method":"tools/call","params":{
        "name":"memory_delete","arguments":{"id":"00000000-0000-4000-8000-000000007777"}}}),
    );
    s.wait_entered(&dir);
    s.signal("TERM");
    let status = s.wait_bounded();
    let stderr = s.stderr_text();
    assert_eq!(status.code(), Some(SIGTERM_CODE), "stderr: {stderr}");
    assert!(
        stderr.contains("did not finish within"),
        "budget expired: {stderr}"
    );
    // Never an acknowledgement for the fenced request.
    assert!(
        s.read_response().is_none(),
        "a request past its budget must not be acknowledged"
    );
    // Its forensic row (queued before the hold) is on disk: 1 pre-signal row
    // from the session start plus this one.
    let recs = rows(home.path());
    assert_eq!(
        delete_rows(&recs),
        2,
        "rows: {:?}",
        recs.iter().map(|r| r.kind.clone()).collect::<Vec<_>>()
    );
    assert_one_unbroken_chain(&recs);
    assert_acked_write_durable(home.path());
}

/// F2 (mid-drain) — the fenced request is released AFTER the budget fence and
/// BEFORE the exit, while the drain is slowed by the writer-delay seam. Only
/// the `commit_ack` refusal keeps it unacknowledged now (the process is still
/// alive and the loop thread wakes up), so removing that refusal turns this
/// cell red. Its forensic row (queued before the hold) is still on disk.
#[test]
fn a_fenced_request_released_mid_drain_is_never_acknowledged_4347() {
    let home = sandbox();
    let dir = barrier_dir(home.path());
    let mut s = Session::start_with(
        home.path(),
        &[
            hold_env(HELD_ID, &dir),
            ("AI_MEMORY_TEST_IN_FLIGHT_BUDGET_MS", "300".to_string()),
            (TEST_FORENSIC_WRITER_DELAY_ENV, "1000".to_string()),
        ],
    );
    s.send(
        &json!({"jsonrpc":"2.0","id":HELD_ID,"method":"tools/call","params":{
        "name":"memory_delete","arguments":{"id":"00000000-0000-4000-8000-000000007777"}}}),
    );
    s.wait_entered(&dir);
    s.signal("TERM");
    // The fence has fired and the (slowed) drain is running: release now.
    s.wait_stderr_contains("the in-flight request did not finish within");
    std::fs::write(dir.join("release"), b"").expect("release mid-drain");
    let resp = s.read_response();
    let status = s.wait_bounded();
    let stderr = s.stderr_text();
    assert_eq!(status.code(), Some(SIGTERM_CODE), "stderr: {stderr}");
    assert!(
        resp.is_none(),
        "a fenced request released mid-drain was acknowledged: {resp:?}; stderr: {stderr}"
    );
    let recs = rows(home.path());
    assert_eq!(
        delete_rows(&recs),
        2,
        "rows: {:?}",
        recs.iter().map(|r| r.kind.clone()).collect::<Vec<_>>()
    );
    assert_one_unbroken_chain(&recs);
    assert_acked_write_durable(home.path());
}

/// B1 — a stop listener that cannot be installed means `mcp` REFUSES TO
/// START: non-zero exit, a clear message, and not one response served.
#[test]
fn an_unavailable_stop_handler_refuses_to_start_4347() {
    for failing in ["SIGTERM", "SIGINT", "SIGHUP"] {
        let home = sandbox();
        let mut child = spawn_mcp(
            home.path(),
            &[(
                "AI_MEMORY_TEST_FAIL_STOP_SIGNAL_INSTALL",
                failing.to_string(),
            )],
            &[],
        );
        // Offer work; a server that started would acknowledge it. A write to
        // an already-exited child may fail: that is the refusal too.
        if let Some(mut stdin) = child.stdin.take() {
            let _ = writeln!(
                stdin,
                "{}",
                json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":"2024-11-05","capabilities":{},
                    "clientInfo":{"name":"probe4347","version":"1"}}})
            );
        }
        let deadline = Instant::now() + STARTUP_BOUND;
        let status = loop {
            if let Some(st) = child.try_wait().expect("try_wait") {
                break st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("mcp kept running with the {failing} handler unavailable");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut out = String::new();
        if let Some(mut o) = child.stdout.take() {
            let _ = o.read_to_string(&mut out);
        }
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        assert!(
            matches!(status.code(), Some(c) if c != 0),
            "{failing}: must exit non-zero, got {status:?}; stderr: {err}"
        );
        assert!(out.trim().is_empty(), "{failing}: served a response: {out}");
        assert!(
            err.contains("refusing to start") && err.contains(failing),
            "{failing}: stderr must say why: {err}"
        );
    }
}

/// #4473 — a SIGHUP / SIGINT the parent left ignored (`nohup`, a background
/// job) stays ignored: the server keeps serving. SIGTERM still stops it
/// gracefully, with the drain.
#[test]
fn an_inherited_ignored_hup_and_int_are_honoured_but_term_still_drains_4347() {
    let home = sandbox();
    let mut s = Session::start_full(home.path(), &[], &[libc::SIGHUP, libc::SIGINT]);
    s.signal("HUP");
    s.signal("INT");
    // Still serving: a round trip after both signals proves they were
    // ignored (a stop would have ended the loop and the process).
    let alive = s.request(&store_request(4000, "served-after-ignored-signals-4347"));
    assert!(alive.get("error").is_none(), "{alive}");
    assert!(
        s.child.try_wait().expect("try_wait").is_none(),
        "an ignored SIGHUP/SIGINT must not stop the server"
    );
    s.signal("TERM");
    let status = s.wait_bounded();
    let stderr = s.stderr_text();
    assert_eq!(status.code(), Some(SIGTERM_CODE), "stderr: {stderr}");
    let recs = rows(home.path());
    assert_eq!(delete_rows(&recs), 1, "the queued row is drained");
    assert_one_unbroken_chain(&recs);
    assert_acked_write_durable(home.path());
    assert_eq!(
        count_title(home.path(), "served-after-ignored-signals-4347"),
        1
    );
}

/// Request id for the `i`-th request of a pipelined burst.
const BURST_BASE_ID: u64 = 100;

fn burst_delete(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
        "name":"memory_delete","arguments":{
            "id":format!("00000000-0000-4000-8000-{id:012}")}}})
}

/// B2 (pipelined form) — 120 requests are queued on stdin and SIGTERM lands
/// at a different point of the burst on every round, so some request is in
/// flight at the signal. Whatever the timing: every ACKNOWLEDGED store is
/// durable, the forensic `memory_delete` rows are exactly the session row
/// plus the ACKNOWLEDGED deletes (no processed request went unacknowledged, no
/// acknowledged one lost its row), and the chain is unbroken.
#[test]
fn a_pipelined_burst_cut_by_sigterm_loses_no_acknowledged_write_4347() {
    const BURST: u64 = 120;
    for round in 0..6_u64 {
        let home = sandbox();
        let mut child = spawn_mcp(home.path(), &[], &[]);
        let mut stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let responses: Arc<Mutex<std::collections::HashMap<u64, Value>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));
        let sink = Arc::clone(&responses);
        let reader = std::thread::spawn(move || {
            for line in stdout.lines() {
                let Ok(line) = line else { break };
                if let Ok(v) = serde_json::from_str::<Value>(&line)
                    && let Some(id) = v.get("id").and_then(Value::as_u64)
                    && let Ok(mut map) = sink.lock()
                {
                    map.insert(id, v);
                }
            }
        });
        // Initialize first and wait for the answer: the stop handlers are
        // installed before the loop serves, so from here a signal is a
        // graceful stop (a signal before that has nothing queued to lose).
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2024-11-05","capabilities":{},
                "clientInfo":{"name":"probe4347","version":"1"}}})
        )
        .expect("write initialize");
        stdin.flush().expect("flush");
        let init_deadline = Instant::now() + STARTUP_BOUND;
        while !responses.lock().is_ok_and(|m| m.contains_key(&1)) {
            // A child that exited at start-up fails now, with its status and
            // stderr, instead of after the full STARTUP_BOUND (#4347 L-2).
            if let Some(status) = child.try_wait().expect("try_wait") {
                let mut err = String::new();
                if let Some(mut e) = child.stderr.take() {
                    let _ = e.read_to_string(&mut err);
                }
                panic!(
                    "round {round}: the child exited ({status:?}) before answering \
                     initialize; stderr:\n{err}"
                );
            }
            assert!(Instant::now() < init_deadline, "no initialize response");
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut payload = String::new();
        payload.push_str(&burst_delete(2).to_string());
        payload.push('\n');
        for k in 0..BURST {
            let id = BURST_BASE_ID + k;
            let req = if k % 3 == 2 {
                store_request(id, &format!("burst-{round}-{id}"))
            } else {
                burst_delete(id)
            };
            payload.push_str(&req.to_string());
            payload.push('\n');
        }
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(payload.as_bytes());
            let _ = stdin.flush();
            stdin
        });
        std::thread::sleep(Duration::from_millis(round * 60));
        let status = Command::new("kill")
            .args(["-s", "TERM", &child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -s TERM failed");
        let deadline = Instant::now() + EXIT_BOUND;
        let exit = loop {
            if let Some(st) = child.try_wait().expect("try_wait") {
                break st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("round {round}: mcp did not exit within {EXIT_BOUND:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let _stdin = writer.join().expect("writer thread");
        reader.join().expect("reader thread");
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        // A signal that arrives before the loop starts reading, or after EOF
        // wins the race, is still a graceful stop with the conventional code.
        assert_eq!(exit.code(), Some(SIGTERM_CODE), "round {round}: {err}");
        let resp = responses.lock().expect("responses").clone();
        let mut acked_deletes = usize::from(resp.contains_key(&2));
        for k in 0..BURST {
            let id = BURST_BASE_ID + k;
            let Some(r) = resp.get(&id) else { continue };
            if k % 3 == 2 {
                assert!(r.get("error").is_none(), "round {round}: {r}");
                assert_eq!(
                    count_title(home.path(), &format!("burst-{round}-{id}")),
                    1,
                    "round {round}: acknowledged store {id} lost"
                );
            } else {
                acked_deletes += 1;
            }
        }
        let recs = rows(home.path());
        if recs.is_empty() {
            // The signal beat the first delete: no row exists, so no TOOL
            // call may have been acknowledged. The initialize response
            // (id 1) is always acknowledged first and is not a tool call.
            let mut acked: Vec<u64> = resp.keys().copied().filter(|id| *id != 1).collect();
            acked.sort_unstable();
            assert!(
                acked.is_empty(),
                "round {round}: tool-call ids {acked:?} acknowledged without a forensic row; {err}"
            );
            continue;
        }
        assert_one_unbroken_chain(&recs);
        assert_eq!(
            delete_rows(&recs),
            acked_deletes,
            "round {round}: forensic delete rows must equal acknowledged deletes; {err}"
        );
    }
}

/// #4347 L-2 (negative check) - a child that exits at start-up makes each
/// start-up wait fail at once, with its exit status and stderr, instead of
/// burning the full `STARTUP_BOUND`. The child is the stop-handler refusal
/// (exits at start-up). Elapsed seconds are printed (`--nocapture`).
#[test]
fn a_child_that_exits_at_start_up_fails_every_start_up_wait_fast_4347() {
    for wait in ["stderr", "entered"] {
        let home = sandbox();
        let mut s = Session::attach(spawn_mcp(
            home.path(),
            &[(
                "AI_MEMORY_TEST_FAIL_STOP_SIGNAL_INSTALL",
                "SIGTERM".to_string(),
            )],
            &[],
        ));
        let dir = barrier_dir(home.path());
        let started = Instant::now();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if wait == "stderr" {
                s.wait_stderr_contains("never-written-needle-4347");
            } else {
                s.wait_entered(&dir);
            }
        }));
        let elapsed = started.elapsed();
        let msg = match caught {
            Ok(()) => panic!("{wait}: the wait returned although the child exited"),
            Err(p) => p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|m| (*m).to_string()))
                .unwrap_or_default(),
        };
        println!("L-2 negative check ({wait}): failed after {elapsed:?}: {msg}");
        assert!(
            msg.contains("the child exited"),
            "{wait}: must name the exit, not a timeout: {msg}"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "{wait}: took {elapsed:?}; STARTUP_BOUND is {STARTUP_BOUND:?}"
        );
    }
}

/// #6142 (TEST-02) - a child that wrote the awaited line and then exited must
/// not fail the wait just because the stderr reader thread had not yet
/// appended that line when `try_wait` reported the exit. The reader is held
/// shut (`attach_gated`) until the child is observed exited, so the
/// "exited, buffer still empty" state is fixed rather than a race. The awaited
/// line is one the refusing child DOES print; the wait must return, not panic.
#[test]
fn a_child_that_exits_after_writing_the_awaited_line_does_not_false_red_the_wait_6142() {
    let home = sandbox();
    let gate = Arc::new(AtomicBool::new(false));
    let mut s = Session::attach_gated(
        spawn_mcp(
            home.path(),
            &[(
                "AI_MEMORY_TEST_FAIL_STOP_SIGNAL_INSTALL",
                "SIGTERM".to_string(),
            )],
            &[],
        ),
        Arc::clone(&gate),
    );
    let deadline = Instant::now() + STARTUP_BOUND;
    while s.child.try_wait().expect("try_wait").is_none() {
        assert!(Instant::now() < deadline, "the refusing child never exited");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        s.stderr_buf.lock().is_ok_and(|b| b.is_empty()),
        "precondition: the reader is gated, the buffer is still empty"
    );
    // Open the gate shortly after the wait starts, so the reader drains the
    // pipe to EOF while the wait is already running.
    let opener = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        gate.store(true, Ordering::Release);
    });
    s.wait_stderr_contains("refusing to start");
    opener.join().expect("opener thread");
}

/// #6142 (TEST-02) - pins the `wait_entered` re-check. The child has exited and
/// the `entered` marker is absent when the wait starts; a helper thread then
/// writes the marker and opens the gate. The wait's loop check sees no marker,
/// `try_wait` sees the exit, `stderr_text()` blocks on the gated reader, and the
/// re-check runs only after the marker exists, so the wait must return. A
/// re-check mutated to `|_| false` panics here ("the child exited ... while
/// waiting for the held request").
#[test]
fn a_child_that_exits_after_writing_the_entered_marker_does_not_false_red_the_wait_6142() {
    let home = sandbox();
    let dir = barrier_dir(home.path());
    let gate = Arc::new(AtomicBool::new(false));
    let mut s = Session::attach_gated(
        spawn_mcp(
            home.path(),
            &[(
                "AI_MEMORY_TEST_FAIL_STOP_SIGNAL_INSTALL",
                "SIGTERM".to_string(),
            )],
            &[],
        ),
        Arc::clone(&gate),
    );
    let deadline = Instant::now() + STARTUP_BOUND;
    while s.child.try_wait().expect("try_wait").is_none() {
        assert!(Instant::now() < deadline, "the refusing child never exited");
        std::thread::sleep(Duration::from_millis(10));
    }
    let marker = dir.join("entered");
    assert!(
        !marker.exists(),
        "precondition: the marker is not written yet"
    );
    let opener = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(&marker, b"x").expect("write the entered marker");
        gate.store(true, Ordering::Release);
    });
    s.wait_entered(&dir);
    opener.join().expect("opener thread");
}
