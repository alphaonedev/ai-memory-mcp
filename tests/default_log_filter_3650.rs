// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #3650 — the shipped log filter must not discard events whose target
//! sits outside `ai_memory`.
//!
//! ## The defect
//!
//! The console subscriber was built from `RUST_LOG` plus an appended
//! `ai_memory=info`. With `RUST_LOG` unset every other target fell to ERROR;
//! with the `RUST_LOG=ai_memory=info` the shipped systemd units exported,
//! every other target was OFF. Hundreds of event sites name such a target
//! (`security.posture`, `store::postgres`, `federation::…`, `signed_events`,
//! `schema_guard`, …), so boot, security, replay and degradation evidence
//! never reached the operator. Separately, the unrecognized-sink WARN on the
//! file/stdout sink fired before that sink's subscriber was installed, so it
//! went nowhere.
//!
//! ## What this pins, against the real binary
//!
//! - a stock `serve` console renders the `security.posture` boot report with
//!   `RUST_LOG` unset, and with the legacy `RUST_LOG=ai_memory=info`;
//! - `RUST_LOG` still narrows: `RUST_LOG=error` hides the same report;
//! - the unrecognized-sink WARN lands in the log file it warns about.
//!
//! The filter's layering rules themselves are unit-tested next to the builder
//! in `src/logging.rs`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// WARN emitted last by the asi-hard boot report (`target: "security.posture"`).
const POSTURE_BANNER: &str = "asi-hard security posture ENGAGED";
/// INFO emitted once per pinned knob, before [`POSTURE_BANNER`].
const POSTURE_PIN_LINE: &str = "asi-hard: pinned security knob";
/// The unrecognized-sink WARN from `logging::init_file_logging`.
const BAD_SINK_WARN: &str = "unrecognized log sink";

/// Scratch dir under `.local-runs/` (project no-`/tmp` HARD RULE).
fn scratch(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-3650-log-filter");
    std::fs::create_dir_all(&root).ok();
    tempfile::Builder::new()
        .prefix(label)
        .tempdir_in(&root)
        .expect("tempdir under .local-runs")
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().expect("local_addr").port()
}

struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// A child with nothing inherited from the host except `PATH`, so the
/// operator's `RUST_LOG`, config and keys cannot leak into the fixture.
fn isolated_command(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir.join("home"))
        .env("XDG_CONFIG_HOME", dir.join("home/.config"))
        .env("AI_MEMORY_KEY_DIR", dir.join("keys"));
    cmd
}

/// Spawn a stock `ai-memory serve` under `asi-hard` with `rust_log` (or no
/// `RUST_LOG` at all) and collect stdout+stderr until the boot banner shows,
/// the child exits, or `budget` elapses.
fn serve_boot_lines(rust_log: Option<&str>, budget: Duration) -> Vec<String> {
    let dir = scratch("serve");
    let witness = dir.path().join("witness-keys");
    std::fs::create_dir_all(&witness).ok();
    let port = free_port().to_string();

    let mut cmd = isolated_command(dir.path());
    cmd.arg("--db")
        .arg(dir.path().join("ai-memory.db"))
        .args(["serve", "--host", "127.0.0.1", "--port", &port])
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_SECURITY_PROFILE", "asi-hard")
        .env("AI_MEMORY_WITNESS_KEY_DIR", &witness)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(value) = rust_log {
        cmd.env("RUST_LOG", value);
    }
    let mut child = cmd.spawn().expect("spawn ai-memory serve");

    let (tx, rx) = mpsc::channel::<String>();
    for stream in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);

    let guard = ChildGuard(Some(child));
    let deadline = Instant::now() + budget;
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(line) => {
                let done = line.contains(POSTURE_BANNER);
                seen.push(line);
                if done {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    drop(guard);
    seen
}

fn assert_posture_report_visible(rust_log: Option<&str>) {
    let lines = serve_boot_lines(rust_log, Duration::from_secs(90));
    for needle in [POSTURE_PIN_LINE, POSTURE_BANNER] {
        assert!(
            lines.iter().any(|l| l.contains(needle)),
            "#3650: with RUST_LOG={rust_log:?} a stock `serve` console must render the \
             `security.posture` boot report ({needle:?}). Before the fix the default filter \
             only admitted targets under `ai_memory`. Captured output:\n{}",
            lines.join("\n")
        );
    }
}

#[test]
fn unset_rust_log_renders_non_ai_memory_boot_events_3650() {
    assert_posture_report_visible(None);
}

#[test]
fn legacy_unit_rust_log_still_renders_non_ai_memory_boot_events_3650() {
    assert_posture_report_visible(Some("ai_memory=info"));
}

/// The operator can still narrow the output: the fix adds a default, it does
/// not override `RUST_LOG`.
#[test]
fn rust_log_error_still_hides_the_boot_report_3650() {
    let lines = serve_boot_lines(Some("error"), Duration::from_secs(20));
    assert!(
        !lines
            .iter()
            .any(|l| l.contains(POSTURE_BANNER) || l.contains(POSTURE_PIN_LINE)),
        "#3650: RUST_LOG=error must still suppress the WARN/INFO boot report. Got:\n{}",
        lines.join("\n")
    );
}

/// The unrecognized-sink WARN reaches the sink it is about.
#[test]
fn unrecognized_sink_warning_reaches_the_log_file_3650() {
    let dir = scratch("sink");
    let logs = dir.path().join("logs");
    let config_dir = dir.path().join("home/.config/ai-memory");
    std::fs::create_dir_all(&config_dir).expect("config dir");
    std::fs::write(
        config_dir.join("config.toml"),
        format!(
            "[logging]\nenabled = true\nsink = \"stout\"\nrotation = \"never\"\npath = {:?}\n",
            logs.to_string_lossy()
        ),
    )
    .expect("write config");

    let out = isolated_command(dir.path())
        .arg("--db")
        .arg(dir.path().join("ai-memory.db"))
        .args(["stats", "--json"])
        .output()
        .expect("spawn ai-memory stats");
    assert!(
        out.status.success(),
        "stats failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut written = String::new();
    for entry in std::fs::read_dir(&logs).expect("log dir created by the file sink") {
        let path = entry.expect("dir entry").path();
        if path.is_file() {
            written.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
        }
    }
    assert!(
        written.contains(BAD_SINK_WARN) && written.contains("stout"),
        "#3650: the unrecognized-sink WARN must land in the file sink it falls back to; \
         before the fix it fired before that sink's subscriber existed. Log file:\n{written}"
    );
}
