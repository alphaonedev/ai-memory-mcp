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

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ai_memory::governance::audit::{CHAIN_HEAD_PREV_HASH, ForensicDecision};
use serde_json::{Value, json};

/// The namespace every probe purges (the forensic row is written before the
/// storage call, so an empty archive is fine).
const PROBE_NAMESPACE: &str = "t4304";

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

/// `mcp` starts (reading row 0 as its tail), a CLI command appends row 1,
/// then `mcp` records a row: it must chain from row 1. Red on the base (it
/// chained from its stale row 0, forking the chain).
#[test]
fn mcp_chains_from_a_row_another_process_wrote_while_it_ran_4304() {
    let home = sandbox();
    purge(home.path(), &[]);
    assert_eq!(rows(home.path()).len(), 1, "seed row");

    let mut child = command(home.path(), &[])
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
    let status = child.wait().expect("mcp exit");
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
