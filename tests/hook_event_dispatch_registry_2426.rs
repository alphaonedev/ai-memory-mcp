// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #2426 — `ai-memory doctor --hooks` must say plainly when a configured hook
//! subscribes to an event that cannot fire.
//!
//! Several `HookEvent` variants parse from `hooks.toml` but have no production
//! dispatch site (`post_store`, `post_delete`, …), and the deny-capable
//! pre-events fire only when the PE-1 enforcement gate is installed
//! (`[hooks].enforce_mode != off` with a non-empty `required_events`). Before
//! the fix, a `hooks.toml` naming such an event loaded cleanly and the doctor
//! listed the hook like any other, with no hint that it would never run.
//!
//! These cells drive the real binary with a `hooks.toml` under a private
//! `XDG_CONFIG_HOME` (Linux only: `dirs::config_dir()` ignores it on macOS).

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use tempfile::TempDir;

/// Write a `hooks.toml` with one enabled exec hook per event, and return the
/// `XDG_CONFIG_HOME` that points at it.
fn hooks_config(tmp: &Path, events: &[&str]) -> PathBuf {
    let xdg = tmp.join("xdg");
    let hooks_dir = xdg.join("ai-memory");
    std::fs::create_dir_all(&hooks_dir).expect("hooks dir");
    let cmd_path = tmp.join("hook-2426.sh");
    std::fs::write(&cmd_path, "#!/bin/sh\nexit 0\n").expect("hook script");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&cmd_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod hook script");
    }
    let mut toml = String::new();
    for event in events {
        toml.push_str(&format!(
            "[[hook]]\nevent = {event:?}\ncommand = {:?}\npriority = 0\ntimeout_ms = 1000\nmode = \"exec\"\nenabled = true\nnamespace = \"*\"\n\n",
            cmd_path.display().to_string(),
        ));
    }
    std::fs::write(hooks_dir.join("hooks.toml"), toml).expect("hooks.toml");
    xdg
}

fn doctor_hooks(tmp: &Path, xdg: &Path, json: bool) -> String {
    let db = tmp.join("doctor-2426.db");
    let mut args = vec!["--db", db.to_str().expect("utf8 db path"), "doctor", "--hooks"];
    if json {
        args.push("--json");
    }
    let out = Command::cargo_bin("ai-memory")
        .expect("ai-memory binary")
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("XDG_CONFIG_HOME", xdg)
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env_remove("AI_MEMORY_HOOKS_ENFORCE_MODE")
        .args(&args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8_lossy(&out).into_owned()
}

/// Human output names every subscribed event that will not fire, and only
/// those: `pre_signal_send` has a live MCP dispatch site and must not be
/// flagged.
#[test]
fn doctor_hooks_names_a_subscription_that_will_never_fire_2426() {
    let tmp = TempDir::new().expect("tempdir");
    let xdg = hooks_config(
        tmp.path(),
        &["post_store", "pre_delete", "pre_recall_expand", "pre_signal_send"],
    );
    let text = doctor_hooks(tmp.path(), &xdg, false);
    let line_for = |event: &str| {
        text.lines()
            .find(|l| l.contains("WARN") && l.contains(&format!("`{event}`")))
            .map(str::to_string)
    };
    let post_store = line_for("post_store").unwrap_or_else(|| {
        panic!("#2426: doctor --hooks must WARN that `post_store` never fires; got:\n{text}")
    });
    assert!(
        post_store.contains("will never fire"),
        "#2426: a post_store hook has no production dispatch site: {post_store}"
    );
    let expand = line_for("pre_recall_expand").unwrap_or_else(|| {
        panic!("#2426: `pre_recall_expand` has no production fire site; got:\n{text}")
    });
    assert!(expand.contains("will never fire"), "{expand}");
    let pre_delete = line_for("pre_delete").unwrap_or_else(|| {
        panic!(
            "#2426: with enforce_mode off, a pre_delete hook is never consulted; \
             doctor --hooks must say so; got:\n{text}"
        )
    });
    assert!(
        pre_delete.contains("enforce_mode"),
        "#2426: the pre_delete WARN must name the enforce gate it depends on: {pre_delete}"
    );
    assert!(
        line_for("pre_signal_send").is_none(),
        "#2426: pre_signal_send has a live dispatch site and must not be flagged:\n{text}"
    );
}

/// JSON output carries the same verdicts, machine-readably.
#[test]
fn doctor_hooks_json_lists_inert_subscriptions_2426() {
    let tmp = TempDir::new().expect("tempdir");
    let xdg = hooks_config(tmp.path(), &["post_store", "pre_signal_send"]);
    let text = doctor_hooks(tmp.path(), &xdg, true);
    let v: serde_json::Value = serde_json::from_str(&text).expect("doctor --hooks --json");
    let inert = v
        .get("inert_subscriptions")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("#2426: missing `inert_subscriptions` array; got:\n{text}"));
    let events: Vec<&str> = inert
        .iter()
        .filter_map(|e| e.get("event").and_then(serde_json::Value::as_str))
        .collect();
    assert_eq!(events, ["post_store"], "{text}");
    assert_eq!(
        inert[0].get("dispatch").and_then(serde_json::Value::as_str),
        Some("never"),
        "{text}"
    );
}
