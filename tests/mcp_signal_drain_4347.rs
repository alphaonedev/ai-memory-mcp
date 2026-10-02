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

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use ai_memory::governance::audit::{
    CHAIN_HEAD_PREV_HASH, ForensicDecision, TEST_FORENSIC_WRITER_DELAY_ENV,
};
use serde_json::{Value, json};

/// Writer delay that makes a queued row certainly outlive a signalled process.
const WRITER_DELAY_MS: &str = "600";

/// How long a signalled child may take to exit before the cell fails.
const EXIT_BOUND: Duration = Duration::from_secs(30);

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
fn spawn_mcp(home: &Path) -> Child {
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
    Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env_clear()
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
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp")
}

struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
}

impl Session {
    /// Spawn, initialize, make one acknowledged write and one forensic row.
    fn start(home: &Path) -> Self {
        let mut child = spawn_mcp(home);
        let stdin = child.stdin.take().expect("stdin");
        let stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut s = Self {
            child,
            stdin: Some(stdin),
            stdout,
        };
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
        s
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

    fn stderr_text(&mut self) -> String {
        let mut text = String::new();
        if let Some(mut e) = self.child.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut e, &mut text);
        }
        text
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
