// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v0.7.x #1590 — `[storage].default_namespace` was resolved
//! (`ResolvedStorage.default_namespace`) but consumed by NO write
//! path: the MCP store defaulted to the compiled `"global"` and the
//! CLI fell straight through to its git-remote → cwd-basename →
//! `"global"` inference ladder.
//!
//! This fresh-subprocess suite pins the boot-seeding link end to end:
//! `daemon_runtime::run` resolves the config, seeds the process-wide
//! configured-default-namespace slot, and the MCP `memory_store`
//! handler consumes it when the caller omits `namespace`.
//!
//! Ladder (highest wins):
//!   explicit caller namespace > configured `[storage].default_namespace`
//!   (ONLY when explicitly set) > historical per-surface default
//!   (`"global"` for MCP/HTTP; git/cwd inference for the CLI — the CLI
//!   legs are pinned at the unit layer in `cli::helpers::tests::
//!   issue_1590_cli_namespace_ladder_config_beats_inference_flag_beats_config`).

#![allow(clippy::missing_panics_doc)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const READ_TIMEOUT: Duration = Duration::from_secs(15);

struct McpChild {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
}

impl Drop for McpChild {
    fn drop(&mut self) {
        drop(self.stdin.take());
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Project-local scratch root (no-/tmp hard rule).
fn scratch_root(tag: &str) -> std::path::PathBuf {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("issue-1590-default-namespace")
        .join(format!("{tag}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("mkdir scratch");
    root
}

/// Write a fake `$HOME` carrying `~/.config/ai-memory/config.toml`
/// with an explicit `[storage].default_namespace`.
fn fake_home_with_config(root: &std::path::Path, default_namespace: &str) -> std::path::PathBuf {
    let home = root.join("home");
    let cfg_dir = home.join(".config").join("ai-memory");
    std::fs::create_dir_all(&cfg_dir).expect("mkdir config dir");
    std::fs::write(
        cfg_dir.join("config.toml"),
        format!("schema_version = 2\n\n[storage]\ndefault_namespace = \"{default_namespace}\"\n"),
    )
    .expect("write config.toml");
    home
}

fn spawn_mcp(
    db_path: &std::path::Path,
    home: Option<&std::path::Path>,
) -> (McpChild, mpsc::Receiver<String>) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    match home {
        Some(h) => {
            // Point the config loader at the fake HOME (and the Linux
            // XDG path) so the child resolves OUR config.toml.
            cmd.env_remove("AI_MEMORY_NO_CONFIG");
            cmd.env("HOME", h);
            cmd.env("XDG_CONFIG_HOME", h.join(".config"));
        }
        None => {
            cmd.env("AI_MEMORY_NO_CONFIG", "1");
        }
    }
    let mut child = cmd
        .args([
            "--db",
            db_path.to_str().unwrap(),
            "mcp",
            "--profile",
            "core",
            "--tier",
            "keyword",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ai-memory mcp");

    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut s = stderr;
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        });
    }
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(line) if !line.trim().is_empty() => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    (
        McpChild {
            child: Some(child),
            stdin: Some(stdin),
        },
        rx,
    )
}

fn send_and_recv(
    stdin: &mut ChildStdin,
    rx: &mpsc::Receiver<String>,
    payload: &serde_json::Value,
) -> serde_json::Value {
    let line = serde_json::to_string(payload).unwrap();
    writeln!(stdin, "{line}").expect("write to mcp stdin");
    stdin.flush().expect("flush mcp stdin");
    let resp = rx
        .recv_timeout(READ_TIMEOUT)
        .expect("mcp response did not arrive within READ_TIMEOUT");
    serde_json::from_str(&resp).unwrap_or_else(|e| panic!("parse mcp response: {e}: {resp}"))
}

fn initialize(stdin: &mut ChildStdin, rx: &mpsc::Receiver<String>) {
    let init = send_and_recv(
        stdin,
        rx,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "issue-1590-probe", "version": "0"}
            }
        }),
    );
    assert!(init.get("result").is_some(), "initialize failed: {init}");
}

/// Drive a `memory_store` WITHOUT a `namespace` argument and return
/// the namespace the response reports.
fn store_omitting_namespace(
    stdin: &mut ChildStdin,
    rx: &mpsc::Receiver<String>,
    title: &str,
) -> String {
    let resp = send_and_recv(
        stdin,
        rx,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "memory_store",
                "arguments": {
                    "title": title,
                    "content": "issue-1590 default-namespace probe body",
                    "tier": "long"
                    // namespace intentionally omitted
                }
            }
        }),
    );
    let text = resp
        .pointer("/result/content/0/text")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("store response missing content text: {resp}"));
    let body: serde_json::Value =
        serde_json::from_str(text).unwrap_or_else(|e| panic!("store body not JSON: {e}: {text}"));
    body["namespace"]
        .as_str()
        .unwrap_or_else(|| panic!("store body missing namespace: {body}"))
        .to_string()
}

/// #1590 regression — with `[storage].default_namespace = "alphaone"`
/// explicitly configured, an MCP `memory_store` that omits `namespace`
/// lands in `alphaone` (pre-fix: hardcoded `"global"`).
#[test]
fn issue_1590_mcp_store_lands_in_configured_default_namespace() {
    let root = scratch_root("configured");
    let home = fake_home_with_config(&root, "alphaone");
    let db_path = root.join("mcp.db");

    let (mut guard, rx) = spawn_mcp(&db_path, Some(&home));
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    let ns = store_omitting_namespace(stdin, &rx, "issue-1590-configured");
    assert_eq!(
        ns, "alphaone",
        "#1590: MCP store must default to the configured [storage].default_namespace"
    );
    drop(guard);
    let _ = std::fs::remove_dir_all(&root);
}

/// #1590 regression — WITHOUT a configured default the historical
/// compiled `"global"` default is preserved (unconfigured deployments
/// must not change behaviour).
#[test]
fn issue_1590_mcp_store_without_config_defaults_to_global() {
    let root = scratch_root("unconfigured");
    let db_path = root.join("mcp.db");

    let (mut guard, rx) = spawn_mcp(&db_path, None);
    let stdin = guard.stdin.as_mut().unwrap();
    initialize(stdin, &rx);
    let ns = store_omitting_namespace(stdin, &rx, "issue-1590-unconfigured");
    assert_eq!(
        ns, "global",
        "unconfigured deployments keep the historical compiled default"
    );
    drop(guard);
    let _ = std::fs::remove_dir_all(&root);
}
