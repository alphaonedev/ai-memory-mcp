// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3650 — the unrecognized-sink fallback WARN must be visible.
//!
//! ## The defect
//!
//! `logging::init_file_logging` emitted its "unrecognized log sink …
//! falling back to the file sink" WARN *before* installing the sink's
//! subscriber. With no subscriber installed the event went nowhere, so
//! a typo like `sink = "stout"` silently misrouted.
//!
//! ## What this pins, against the real binary
//!
//! - presence (same `file` sink): `sink = "stout"` + `stats` lands the
//!   WARN in the log file it warns about;
//! - absence (same `file` sink): `sink = "file"` lands no such WARN.
//!
//! Scratch lives under `.local-runs/` (project no-`/tmp` rule); the
//! child runs with a cleared environment so the operator's `RUST_LOG`,
//! config and keys cannot leak into the fixture.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// WARN text emitted by `logging::init_file_logging` for a bad sink.
const BAD_SINK_WARN: &str = "unrecognized log sink";

fn scratch_3650(label: &str) -> tempfile::TempDir {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(".local-runs")
        .join("issue-3650-sink-warn");
    std::fs::create_dir_all(&root).expect("scratch root");
    tempfile::Builder::new()
        .prefix(label)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn isolated_command_3650(dir: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir.join("home"))
        .env("XDG_CONFIG_HOME", dir.join("home/.config"))
        .env("AI_MEMORY_KEY_DIR", dir.join("keys"));
    cmd
}

fn write_logging_config_3650(dir: &Path, sink: &str, logs: &Path) {
    let config_dir = dir.join("home/.config/ai-memory");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        format!(
            "[logging]\nenabled = true\nsink = \"{sink}\"\nrotation = \"never\"\npath = \"{}\"\n",
            logs.to_string_lossy()
        ),
    )
    .expect("write config");
}

/// Run `stats` once against a scratch sqlite DB and return when the
/// rolling appender's directory holds `needle`, or the budget elapses.
/// Returns every line collected across the directory's log files.
fn run_stats_until_3650(dir: &Path, logs: &Path, needle: &str, budget: Duration) -> String {
    let out = isolated_command_3650(dir)
        .arg("--db")
        .arg(dir.join("ai-memory.db"))
        .args(["stats", "--json"])
        .output()
        .expect("spawn ai-memory stats");
    assert!(
        out.status.success(),
        "#3650: stats failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let deadline = Instant::now() + budget;
    let mut body = String::new();
    while Instant::now() < deadline {
        body.clear();
        if let Ok(entries) = std::fs::read_dir(logs) {
            let mut files: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .collect();
            files.sort();
            for file in files {
                if let Ok(text) = std::fs::read_to_string(&file) {
                    body.push_str(&text);
                    body.push('\n');
                }
            }
        }
        if body.contains(needle) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    body
}

#[test]
fn unrecognized_sink_warning_reaches_the_log_file_3650() {
    let dir = scratch_3650("bad-sink");
    let logs = dir.path().join("logs");
    write_logging_config_3650(dir.path(), "stout", &logs);
    let body = run_stats_until_3650(dir.path(), &logs, BAD_SINK_WARN, Duration::from_secs(25));
    assert!(
        body.contains(BAD_SINK_WARN),
        "#3650: with sink = \"stout\" the fallback WARN must land in the \
         log file it warns about. Before the fix it fired before the \
         subscriber existed and went nowhere. Captured:\n{body}"
    );
}

#[test]
fn recognized_sink_produces_no_spurious_warning_3650() {
    let dir = scratch_3650("good-sink");
    let logs = dir.path().join("logs");
    write_logging_config_3650(dir.path(), "file", &logs);
    let body = run_stats_until_3650(dir.path(), &logs, BAD_SINK_WARN, Duration::from_secs(25));
    assert!(
        !body.contains(BAD_SINK_WARN),
        "#3650: with sink = \"file\" no fallback WARN may appear. Got:\n{body}"
    );
}
