// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! v1.0.0 #2908 — the boot security-posture banner must be VISIBLE on a stock
//! `ai-memory serve` console.
//!
//! ## The defect
//!
//! On a default config `[logging].enabled` is OFF, so `main`'s
//! `logging::init_file_logging` installs NO subscriber, and the console
//! subscriber was installed only inside `serve()` — which runs AFTER
//! `daemon_runtime::run`'s common boot-report block. Both the asi-hard #1961
//! pin report and the §5.3 `security.posture.enterprise_federation` banner
//! (#2905) were therefore emitted into a VOID: 0 banner lines with
//! `RUST_LOG=info` and no config.
//!
//! That is cert-load-bearing. The §5.3 cutline ruling mandates "a boot banner
//! echoing the effective posture", and its cited precedent is "verify the
//! banner, never infer from env" — a banner nobody can see cannot be cited as
//! evidence.
//!
//! ## What this pins
//!
//! - `serve` emits the boot posture banner on a stock console (no config,
//!   `RUST_LOG=info`) — the regression this issue is about;
//! - a CLI one-shot still emits NOTHING, because the install is deliberately
//!   SCOPED to the commands that install this same subscriber anyway. An
//!   unconditional install would change every subcommand's captured
//!   stdout/stderr (see the COVERAGE NOTE in `src/main.rs` and the module doc
//!   of `tests/security_profile_dispatch_1961.rs`, which asserts exactly that
//!   CLI one-shots render no tracing output).
//!
//! The banner is emitted BEFORE daemon bootstrap, so this test does not
//! require the daemon to finish coming up — only to reach the boot-report
//! block.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The asi-hard boot banner emitted from `daemon_runtime::run`'s posture
/// report block (`target: "security.posture"`).
const ASI_HARD_BANNER: &str = "asi-hard security posture ENGAGED";

/// Scratch dir under `.local-runs/` (project no-`/tmp` HARD RULE).
fn scratch(label: &str) -> tempfile::TempDir {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".local-runs")
        .join("issue-2908-boot-banner");
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

/// Spawn a stock `ai-memory serve` under the `asi-hard` posture and return
/// every line it emitted on stdout+stderr until `needle` appeared, the child
/// exited, or the budget elapsed.
fn serve_boot_lines(needle: &str, budget: Duration) -> Vec<String> {
    let dir = scratch("serve-banner");
    let db = dir.path().join("ai-memory.db");
    let keys = dir.path().join("witness-keys");
    std::fs::create_dir_all(&keys).ok();
    let port = free_port().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .arg("--db")
        .arg(&db)
        .args(["serve", "--host", "127.0.0.1", "--port", &port])
        // A STOCK console: no config file, so `[logging].enabled` is off and
        // NO subscriber is installed by `main` — the exact condition under
        // which the banner used to vanish.
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("RUST_LOG", "info")
        // Arms the boot report the banner belongs to. A genuinely fresh node
        // (fresh db + fresh witness dir) boots clean under asi-hard per the
        // #2942 cold-boot carve-out pinned in
        // `tests/security_profile_dispatch_1961.rs`.
        .env("AI_MEMORY_SECURITY_PROFILE", "asi-hard")
        .env("AI_MEMORY_WITNESS_KEY_DIR", &keys)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ai-memory serve");

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
    let mut seen: Vec<String> = Vec::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(line) => {
                let hit = line.contains(needle);
                seen.push(line);
                if hit {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            // Both readers ended: the child exited and closed its pipes.
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    drop(guard);
    seen
}

/// A stock `ai-memory serve` console MUST render the boot posture banner.
#[test]
fn stock_serve_console_renders_the_boot_posture_banner_2908() {
    let lines = serve_boot_lines(ASI_HARD_BANNER, Duration::from_secs(90));
    assert!(
        lines.iter().any(|l| l.contains(ASI_HARD_BANNER)),
        "#2908: a stock `ai-memory serve` (no config, RUST_LOG=info) must render the boot \
         security-posture banner. Pre-fix the console subscriber was installed inside \
         `serve()` — AFTER `run()`'s boot-report block — so on a default deployment \
         ([logging].enabled = off) the asi-hard #1961 report and the §5.3 #2905 banner were \
         emitted into a void, and the certification could not cite the banner as evidence. \
         Captured output:\n{}",
        lines.join("\n")
    );
}

/// The install is SCOPED: a CLI one-shot must still render no tracing output,
/// so every non-daemon subcommand's stdout/stderr stays byte-identical.
#[test]
fn cli_one_shot_still_installs_no_console_subscriber_2908() {
    let dir = scratch("cli-oneshot");
    let db = dir.path().join("ai-memory.db");
    let out = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .arg("--db")
        .arg(&db)
        .args(["stats", "--json"])
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("RUST_LOG", "info")
        .env("AI_MEMORY_SECURITY_PROFILE", "asi-hard")
        .env("AI_MEMORY_WITNESS_KEY_DIR", dir.path())
        .output()
        .expect("spawn ai-memory stats");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains(ASI_HARD_BANNER),
        "#2908: the boot-time subscriber install must stay scoped to the daemon/console \
         commands; a CLI one-shot rendering tracing output would change every subcommand's \
         captured stdout/stderr. Got:\n{combined}"
    );
}
