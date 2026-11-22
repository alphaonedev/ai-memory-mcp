// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4304 — one forensic chain across processes.
//!
//! A long-lived `mcp` process read the chain tail once at start and chained
//! every later row from its own head, so a row a CLI command appended while it
//! ran was skipped: the chain forked, and `verify` reported a break with no
//! tampering. Every append now takes `<forensic dir>/forensic.lock` and
//! re-reads the tail when the file changed since this process last wrote
//! (vote acba9602).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use ai_memory::governance::audit::{CHAIN_HEAD_PREV_HASH, ForensicDecision};
use serde_json::{Value, json};
// #9906 F1: the one guard of every spawned child, shared by the three drain
// test files.
#[path = "common/mcp_child_guard.rs"]
mod mcp_child_guard;
use mcp_child_guard::{ChildGuard, TIER_LINE, requested_tiers, spawn_line_reader};

/// The namespace every probe purges (the forensic row is written before the
/// storage call, so an empty archive is fine).
const PROBE_NAMESPACE: &str = "t4304";

/// #9906 — the tier every child serves (config file and `mcp --tier`).
const CHILD_TIER: &str = "keyword";

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
            "schema_version = 2\ntier = \"{CHILD_TIER}\"\n\n[audit]\nenabled = false\npath = \"{}\"\n",
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

/// How long a child may take to answer one request line (start-up included:
/// scheduler-bound on a loaded host, so generous, but a bound).
const RESPONSE_BOUND: Duration = Duration::from_secs(300);

/// How long a child may take to exit after stdin EOF.
const EXIT_BOUND: Duration = Duration::from_secs(60);

/// The one spawn site of an `mcp` child in this file: the guard owns it, so
/// every failed wait kills and reaps it and reports its stderr (#9906 F1).
fn spawn_mcp(home: &Path) -> ChildGuard {
    let child = command(home, &[])
        // #9906 — the tier on the command line: `mcp --tier` has a clap
        // default that shadows the config file's tier (#9913).
        .args(["mcp", "--profile", "full", "--tier", CHILD_TIER])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp");
    ChildGuard::new(child)
}

/// `mcp` starts (reading row 0 as its tail), a CLI command appends row 1,
/// then `mcp` records a row: it must chain from row 1. Red on the base (it
/// chained from its stale row 0, forking the chain).
#[test]
fn mcp_chains_from_a_row_another_process_wrote_while_it_ran_4304() {
    let home = sandbox();
    purge(home.path(), &[]);
    assert_eq!(rows(home.path()).len(), 1, "seed row");

    let mut guard = spawn_mcp(home.path());
    let mut stdin = guard.take_stdin().expect("stdin");
    let lines = spawn_line_reader(guard.take_stdout().expect("stdout"));
    let mut request = |req: &Value| -> Value {
        guard.write_line(&mut stdin, "request", &req.to_string());
        let Some(line) = guard.recv_line(&lines, RESPONSE_BOUND, "a response line") else {
            guard.fail("a response line (stdout closed)", None)
        };
        serde_json::from_str(&line).expect("json response")
    };
    // The answer to `initialize` proves `mcp` is up, so its sink (and the
    // tail it read) predates the next CLI row.
    let init = request(
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2024-11-05","capabilities":{},
        "clientInfo":{"name":"probe4304","version":"1"}}}),
    );
    assert!(init.get("error").is_none(), "initialize: {init}");

    purge(home.path(), &[]);
    assert_eq!(
        rows(home.path()).len(),
        2,
        "the CLI row landed while mcp ran"
    );

    // `memory_delete` records its forensic row before the permission gate.
    let _ = request(
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{
        "name":"memory_delete","arguments":{"id":"00000000-0000-4000-8000-000000004304"}}}),
    );
    drop(stdin);
    let status = guard.wait_exit_bounded(EXIT_BOUND, "mcp to exit after stdin EOF");
    assert!(status.success(), "mcp exit status: {status}");

    let recs = rows(home.path());
    assert_eq!(
        recs.iter()
            .map(|r| r.kind.as_str())
            .collect::<Vec<_>>()
            .last(),
        Some(&"memory_delete"),
        "the mcp row is last"
    );
    assert_eq!(recs.len(), 3);
    assert_one_unbroken_chain(&recs);
}

/// #9906 — the `mcp` child of this file serves the keyword tier. The config
/// file's `tier = "keyword"` alone does not reach `mcp` (#9913), so the spawn
/// pins it on the command line; this cell is red when it does not.
#[test]
fn the_mcp_child_serves_the_keyword_tier_9906() {
    let home = sandbox();
    let mut guard = spawn_mcp(home.path());
    guard.wait_stderr_contains(TIER_LINE, RESPONSE_BOUND);
    drop(guard.take_stdin());
    let status = guard.wait_exit_bounded(EXIT_BOUND, "mcp to exit after stdin EOF");
    let err = guard.stderr_final();
    assert_eq!(
        requested_tiers(&err),
        [CHILD_TIER],
        "requested tier lines; stderr:\n{err}"
    );
    assert!(
        status.success(),
        "mcp exit status: {status}; stderr:\n{err}"
    );
}
