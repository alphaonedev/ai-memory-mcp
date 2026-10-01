// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4319 — a forensic row is never lost because its process exited.
//!
//! `governance::audit::append_row` advanced the chain head and only ENQUEUED
//! the row to the background writer (#1472); nothing drained that queue
//! before exit, so a short-lived command could exit with its row still
//! queued: 41 contended `archive purge` runs left 38 rows (r1). The vote
//! (decision 5c424459) chose: every process writes its rows INLINE before
//! recording returns, except the long-running request servers (`serve`,
//! `mcp`), which keep the background writer and drain it at exit, bounded.
//!
//! The debug-build knob `AI_MEMORY_TEST_FORENSIC_WRITER_DELAY_MS` delays the
//! background writer, which turns "the process exits while its row is still
//! queued" from a race into a certainty. Red on the carrier: with the delay,
//! every short-lived run loses its row.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ai_memory::governance::audit::{
    CHAIN_HEAD_PREV_HASH, ForensicDecision, TEST_FORENSIC_WRITER_DELAY_ENV,
};
use serde_json::{Value, json};

/// The namespace every probe purges (the forensic row is written before the
/// storage call, so an empty archive is fine).
const PROBE_NAMESPACE: &str = "t4319";

/// Writer delay that makes a queued row certainly outlive a short process.
const WRITER_DELAY_MS: &str = "400";

/// Short-lived runs per cell.
const RUNS: usize = 12;

fn sandbox() -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".local-runs");
    std::fs::create_dir_all(&root).expect("create test scratch root");
    tempfile::tempdir_in(root).expect("isolated test directory")
}

fn forensic_dir(home: &Path) -> PathBuf {
    home.join("audit")
}

/// The CLI, isolated: its own config (flat trail off, forensic dir here),
/// its own key dir, the given extra env.
fn command(home: &Path, env: &[(&str, &str)]) -> Command {
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
        );
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.current_dir(home)
        .arg("--db")
        .arg(home.join("forensic.db"));
    cmd
}

fn purge(home: &Path, env: &[(&str, &str)]) {
    let out = command(home, env)
        .args(["archive", "purge", "--namespace", PROBE_NAMESPACE])
        .output()
        .expect("run archive purge");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
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

/// `RUNS` short-lived commands, each one forensic row, with the background
/// writer slowed so a queued row certainly outlives its process: every row
/// must still be on disk. Red on the carrier (each process exited with its
/// row in the queue: 0 rows).
#[test]
fn short_lived_commands_never_lose_their_forensic_row_4319() {
    let home = sandbox();
    let env = [(TEST_FORENSIC_WRITER_DELAY_ENV, WRITER_DELAY_MS)];
    for _ in 0..RUNS {
        purge(home.path(), &env);
    }
    let recs = rows(home.path());
    assert_eq!(
        recs.len(),
        RUNS,
        "every short-lived run must leave its forensic row ({} of {RUNS})",
        recs.len()
    );
    assert_one_unbroken_chain(&recs);
}

/// Control: without the delay the same holds (the inline path is the normal
/// path, not a test artefact).
#[test]
fn short_lived_commands_write_their_row_without_the_delay_4319() {
    let home = sandbox();
    for _ in 0..RUNS {
        purge(home.path(), &[]);
    }
    let recs = rows(home.path());
    assert_eq!(recs.len(), RUNS);
    assert_one_unbroken_chain(&recs);
}

/// The background mode: `mcp` queues its rows on the background writer, and
/// the exit drain must persist them when the process ends (stdin EOF), even
/// with the writer slowed. Red on the carrier: the row was still queued.
#[test]
fn mcp_drains_its_queued_forensic_rows_at_exit_4319() {
    let home = sandbox();
    let mut child = command(
        home.path(),
        &[(TEST_FORENSIC_WRITER_DELAY_ENV, WRITER_DELAY_MS)],
    )
    .args(["mcp", "--profile", "full"])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .expect("spawn mcp");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut request = |req: &Value| -> Value {
        writeln!(stdin, "{req}").expect("write request");
        stdin.flush().expect("flush");
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read response");
        serde_json::from_str(&line).expect("json response")
    };
    let init = request(
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2024-11-05","capabilities":{},
        "clientInfo":{"name":"probe4319","version":"1"}}}),
    );
    assert!(init.get("error").is_none(), "initialize: {init}");
    // `memory_delete` records its forensic row before the permission gate,
    // so a delete of an id that does not exist still writes one row.
    let _ = request(
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
        "name":"memory_delete","arguments":{"id":"00000000-0000-4000-8000-000000004319"}}}),
    );
    drop(stdin);
    let status = child.wait().expect("mcp exit");
    assert!(status.success(), "mcp exit status: {status}");

    let recs = rows(home.path());
    assert!(
        recs.iter().any(|r| r.kind == "memory_delete"),
        "the row queued by the mcp process must be on disk after it exits; rows: {:?}",
        recs.iter().map(|r| r.kind.clone()).collect::<Vec<_>>()
    );
    assert_one_unbroken_chain(&recs);
}
