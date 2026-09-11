// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3587 U4 — acceptance tests for
//! `ai-memory install claude-code --hook capture` (the Claude Code `Stop`
//! hook sink for `ai-memory capture-turn`), driven through the real binary.
//!
//! Pins:
//! - `install_capture_hook_is_idempotent_3587` — two `--apply` runs leave
//!   exactly ONE managed `hooks.Stop` entry, shaped as a no-matcher
//!   `type:command` `async:true` entry whose command invokes
//!   `capture-turn --host-kind claude-code --quiet --agent-id <resolved>`.
//! - `install_capture_hook_uninstall_leaves_operator_hooks_3587` — the
//!   uninstall removes only our managed Stop entry and preserves
//!   operator-authored Stop hooks.
//! - `install_capture_hook_rejected_on_non_claude_code_3587` — a
//!   non-claude-code target refuses `--hook capture` loudly (cursor keeps
//!   the generic pinned refusal; codex names the documented transcript/line
//!   source equivalent).
//!
//! Each test uses a tempdir + `--config` so the real `~/.claude/settings.json`
//! is never touched.

use std::process::Command as StdCommand;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const AGENT_ID: &str = "test-agent-3587";

fn write(path: &std::path::Path, body: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, body).unwrap();
}

fn read_json(path: &std::path::Path) -> Value {
    let s = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&s).unwrap()
}

/// `ai-memory --agent-id <id> install <target> --config <cfg> ...`
fn install_cmd(target: &str, cfg: &std::path::Path, extra: &[&str]) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").unwrap();
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .arg("--agent-id")
        .arg(AGENT_ID)
        .args(["install", target, "--config"])
        .arg(cfg)
        .args(extra);
    cmd
}

/// The managed Stop entry the installer writes (the sole array element
/// when no operator Stop hook exists).
fn managed_stop_entry(parsed: &Value) -> &Value {
    let arr = parsed["hooks"]["Stop"]
        .as_array()
        .unwrap_or_else(|| panic!("hooks.Stop must be an array; got {parsed}"));
    assert_eq!(arr.len(), 1, "exactly one managed Stop entry; got {arr:?}");
    &arr[0]
}

#[test]
fn install_capture_hook_is_idempotent_3587() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("settings.json");
    write(&cfg, "{}\n");

    // Two --apply runs: the second must replace, not duplicate, our entry.
    for _ in 0..2 {
        install_cmd("claude-code", &cfg, &["--hook", "capture", "--apply"])
            .assert()
            .success();
    }

    let parsed = read_json(&cfg);
    let entry = managed_stop_entry(&parsed);
    // No `matcher` on a Stop hook.
    assert!(
        entry.get("matcher").is_none(),
        "Stop capture entry must not carry a matcher; got {entry}"
    );
    // `async: true` keeps capture off the host's critical path (F11).
    assert_eq!(entry["hooks"][0]["type"], "command", "got {entry}");
    assert_eq!(entry["hooks"][0]["async"], Value::Bool(true), "got {entry}");
    // Managed-keys allowlist is `["hooks"]` for this block.
    assert_eq!(
        entry["// ai-memory:managed-keys"][0], "hooks",
        "got {entry}"
    );

    let command = entry["hooks"][0]["command"]
        .as_str()
        .expect("command must be a string");
    assert!(
        command.contains("capture-turn --host-kind claude-code --quiet --agent-id"),
        "generated command must invoke the quiet capture-turn twin; got {command}"
    );
    assert!(
        command.contains(AGENT_ID),
        "generated command must embed the explicitly resolved agent id; got {command}"
    );
}

#[test]
fn install_capture_hook_uninstall_leaves_operator_hooks_3587() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("settings.json");
    // An operator-authored Stop hook that must survive both directions.
    write(
        &cfg,
        r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo operator-stop"}]}]}}"#,
    );

    install_cmd("claude-code", &cfg, &["--hook", "capture", "--apply"])
        .assert()
        .success();
    let parsed = read_json(&cfg);
    assert_eq!(
        parsed["hooks"]["Stop"].as_array().unwrap().len(),
        2,
        "operator entry + our managed entry"
    );

    install_cmd(
        "claude-code",
        &cfg,
        &["--hook", "capture", "--uninstall", "--apply"],
    )
    .assert()
    .success();

    let parsed = read_json(&cfg);
    let arr = parsed["hooks"]["Stop"]
        .as_array()
        .expect("operator Stop hook must survive uninstall");
    assert_eq!(arr.len(), 1, "only the operator entry remains; got {arr:?}");
    assert_eq!(
        arr[0]["hooks"][0]["command"], "echo operator-stop",
        "operator-authored Stop hook is preserved verbatim"
    );
}

#[test]
fn install_capture_hook_rejected_on_non_claude_code_3587() {
    let tmp = TempDir::new().unwrap();

    // Generic non-claude-code target keeps the pinned refusal.
    let cursor_cfg = tmp.path().join("cursor.json");
    write(&cursor_cfg, "{}\n");
    install_cmd("cursor", &cursor_cfg, &["--hook", "capture", "--apply"])
        .assert()
        .failure()
        .stderr(predicates::str::contains(
            "only supported for `claude-code`",
        ));

    // Codex has no installable turn-capture hook (see the installer's
    // cited Codex-leg rationale), so it refuses with the documented
    // transcript/line source instead of silently installing a dead hook.
    let codex_cfg = tmp.path().join("codex.toml");
    write(&codex_cfg, "\n");
    install_cmd("codex", &codex_cfg, &["--hook", "capture", "--apply"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("watch --host codex"));
}

/// The install must not have written anything when it refuses.
#[test]
fn install_capture_hook_rejection_does_not_touch_config_3587() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("cursor.json");
    let original = "{\"unchanged\":true}\n";
    write(&cfg, original);

    let out = StdCommand::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args([
            "install",
            "cursor",
            "--config",
            cfg.to_str().unwrap(),
            "--hook",
            "capture",
            "--apply",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(std::fs::read_to_string(&cfg).unwrap(), original);
}
