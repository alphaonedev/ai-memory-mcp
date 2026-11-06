// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8193 umbrella (Ctrl-C and SIGTERM handling): one shared shutdown
//! primitive, `ai_memory::stop_signal`, for every long-running verb.
//!
//! * #6385 / #6869: a `tokio::signal::ctrl_c()` registration error is an
//!   error, never a received interrupt. The class is locked by a source scan:
//!   no `ctrl_c()` call outside the two reviewed homes, and every daemon
//!   source names the shared primitive.
//! * `sync-daemon` (previously SIGINT only): SIGTERM now takes the graceful
//!   path and exits 0, exactly as SIGINT does.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The only sources allowed to call `tokio::signal::ctrl_c()` directly: the
/// shared primitive and the fail-closed `mcp` stop listeners.
const CTRL_C_ALLOWED: [&str; 2] = ["src/stop_signal.rs", "src/mcp/shutdown.rs"];

/// Needle for a direct interrupt registration.
const CTRL_C_NEEDLE: &str = "signal::ctrl_c(";

/// Daemon sources that must route their stop wait through the primitive.
const DAEMON_SOURCES: [&str; 6] = [
    "src/daemon_runtime.rs",
    "src/cli/wake_hub.rs",
    "src/cli/wake_listen.rs",
    "src/cli/watch.rs",
    "src/cli/curator.rs",
    "src/cli/sync.rs",
];

/// Marker proving a daemon source uses the shared primitive.
const PRIMITIVE_MARKER: &str = "stop_signal::";

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// #6385 + #6869: no `tokio::signal::ctrl_c()` outside the reviewed homes.
#[test]
fn no_direct_ctrl_c_registration_outside_the_primitive_6869() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_sources(&root.join("src"), &mut files);
    let mut offenders = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if CTRL_C_ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap();
        for (idx, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            if line.contains(CTRL_C_NEEDLE) {
                offenders.push(format!("{rel}:{}", idx + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "#6869: direct ctrl_c() registration outside the shared primitive: {offenders:?}"
    );
}

/// Every long-running verb's source names the shared primitive.
#[test]
fn every_daemon_uses_the_shared_primitive_8193() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let missing: Vec<&str> = DAEMON_SOURCES
        .iter()
        .copied()
        .filter(|rel| {
            !std::fs::read_to_string(root.join(rel))
                .unwrap()
                .contains(PRIMITIVE_MARKER)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "#8193: daemon sources not using the shared stop primitive: {missing:?}"
    );
}

/// Boot line `sync-daemon` logs before it waits for a stop signal.
#[cfg(unix)]
const SYNC_BOOT_MARKER: &str = "sync-daemon: local_agent_id";

/// Bound on waiting for the boot line, and on the exit after the signal.
#[cfg(unix)]
const SYNC_WAIT_DEADLINE: Duration = Duration::from_secs(60);

/// Pause after the boot line so the stop listeners are installed.
#[cfg(unix)]
const SYNC_SETTLE: Duration = Duration::from_millis(750);

/// Poll interval while waiting for the daemon to exit.
#[cfg(unix)]
const SYNC_POLL: Duration = Duration::from_millis(100);

/// A peer URL nothing listens on: the daemon only has to boot and wait.
#[cfg(unix)]
const SYNC_UNREACHABLE_PEER: &str = "https://127.0.0.1:9";

/// `sync-daemon` takes SIGINT and SIGTERM down the same graceful path (exit 0).
#[cfg(unix)]
#[test]
fn sync_daemon_stop_signals_exit_zero_8193() {
    use std::os::unix::process::ExitStatusExt;

    for (name, signal) in [("SIGINT", libc::SIGINT), ("SIGTERM", libc::SIGTERM)] {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = tmp.path().join("sync-8193.db");
        let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .arg("--db")
            .arg(&db)
            .args(["sync-daemon", "--peers", SYNC_UNREACHABLE_PEER])
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_AGENT_ID", "ai:sync-8193")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, rx) = mpsc::channel::<String>();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        let deadline = Instant::now() + SYNC_WAIT_DEADLINE;
        let mut log = String::new();
        let mut booted = false;
        while Instant::now() < deadline {
            if let Ok(line) = rx.recv_timeout(SYNC_POLL) {
                log.push_str(&line);
                log.push('\n');
                if line.contains(SYNC_BOOT_MARKER) {
                    booted = true;
                    break;
                }
            } else if child.try_wait().unwrap().is_some() {
                break;
            }
        }
        if !booted {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{name}: sync-daemon did not boot:\n{log}");
        }
        std::thread::sleep(SYNC_SETTLE);
        // SAFETY: the pid is this test's own, still-owned child.
        unsafe {
            libc::kill(i32::try_from(child.id()).unwrap(), signal);
        }
        let status = loop {
            if Instant::now() > deadline + SYNC_WAIT_DEADLINE {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{name}: sync-daemon did not exit after the signal");
            }
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            std::thread::sleep(SYNC_POLL);
        };
        let _ = reader.join();
        assert_eq!(status.signal(), None, "{name}: died by signal");
        assert!(status.success(), "{name}: exit {status:?}");
    }
}
