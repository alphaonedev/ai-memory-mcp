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

/// Bound on waiting for a verb's boot line, and on its exit after a signal.
#[cfg(unix)]
const VERB_WAIT_DEADLINE: Duration = Duration::from_secs(60);

/// Pause after the boot line so the stop listeners are installed.
#[cfg(unix)]
const VERB_SETTLE: Duration = Duration::from_millis(750);

/// Poll interval while waiting for a verb to boot or exit.
#[cfg(unix)]
const VERB_POLL: Duration = Duration::from_millis(100);

/// Both stop signals every verb must take down the same graceful path.
#[cfg(unix)]
const STOP_SIGNALS: [(&str, libc::c_int); 2] =
    [("SIGINT", libc::SIGINT), ("SIGTERM", libc::SIGTERM)];

/// A peer URL nothing listens on: the daemon only has to boot and wait.
#[cfg(unix)]
const SYNC_UNREACHABLE_PEER: &str = "https://127.0.0.1:9";

/// Boot line `sync-daemon` logs before it waits for a stop signal.
#[cfg(unix)]
const SYNC_BOOT_MARKER: &str = "sync-daemon: local_agent_id";

/// Boot line `wake-hub` logs once its socket is bound and it is serving.
#[cfg(unix)]
const WAKE_HUB_BOOT_MARKER: &str = "wake-hub: listening";

/// Line `wake-hub` logs once its drain finished.
#[cfg(unix)]
const WAKE_HUB_STOPPED_MARKER: &str = "wake-hub: stopped";

/// Boot line `wake-listen` logs before it waits for a wake.
#[cfg(unix)]
const WAKE_LISTEN_BOOT_MARKER: &str = "wake listener: started";

/// Line `wake-listen` logs when it stops on a signal.
#[cfg(unix)]
const WAKE_LISTEN_STOPPING_MARKER: &str = "wake listener: stopping on signal";

/// Boot line `watch --daemon` logs before its first poll.
#[cfg(unix)]
const WATCH_BOOT_MARKER: &str = "L3 watch daemon started";

/// Line `watch --daemon` logs once its loop has stopped.
#[cfg(unix)]
const WATCH_STOPPED_MARKER: &str = "L3 watch daemon shutdown";

/// Boot line `curator --daemon` logs before its first cycle.
#[cfg(unix)]
const CURATOR_BOOT_MARKER: &str = "curator daemon started";

/// How long the `wake-listen` test hook sleeps: long enough that the signal
/// is delivered while the hook runs, short enough to finish well inside the
/// exit deadline.
#[cfg(unix)]
const HOOK_SLEEP_SECS: u32 = 3;

/// A spawned verb under test: its child, its streamed stderr and the temp dir
/// that owns every path it touches.
#[cfg(unix)]
struct Verb {
    child: std::process::Child,
    rx: mpsc::Receiver<String>,
    reader: Option<std::thread::JoinHandle<()>>,
    log: String,
    _tmp: tempfile::TempDir,
}

#[cfg(unix)]
impl Verb {
    /// Spawn `ai-memory --db <tmp>/verb-8193.db <args>` with an isolated home
    /// and no config, stderr streamed line by line.
    fn spawn(args: &[&str]) -> Self {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = tmp.path().join("verb-8193.db");
        let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
            .arg("--db")
            .arg(&db)
            .args(args)
            .env("AI_MEMORY_NO_CONFIG", "1")
            .env("AI_MEMORY_AGENT_ID", "ai:verb-8193")
            .env("HOME", tmp.path())
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
        Self {
            child,
            rx,
            reader: Some(reader),
            log: String::new(),
            _tmp: tmp,
        }
    }

    /// Drain pending stderr lines into the log for up to `wait`.
    fn pump(&mut self, wait: Duration) {
        if let Ok(line) = self.rx.recv_timeout(wait) {
            self.log.push_str(&line);
            self.log.push('\n');
        }
    }

    /// Kill the child (it is this test's own) and fail with the log.
    fn fail(&mut self, why: &str) -> ! {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.pump(Duration::from_millis(50));
        panic!("{why}:\n{}", self.log);
    }

    /// Wait until the log shows `marker`.
    fn wait_for_log(&mut self, marker: &str) {
        let deadline = Instant::now() + VERB_WAIT_DEADLINE;
        while Instant::now() < deadline {
            self.pump(VERB_POLL);
            if self.log.contains(marker) {
                return;
            }
            if self.child.try_wait().unwrap().is_some() {
                self.fail(&format!("verb exited before logging {marker:?}"));
            }
        }
        self.fail(&format!("verb never logged {marker:?}"));
    }

    /// Wait until `path` exists.
    fn wait_for_file(&mut self, path: &Path) {
        let deadline = Instant::now() + VERB_WAIT_DEADLINE;
        while Instant::now() < deadline {
            if path.exists() {
                return;
            }
            self.pump(VERB_POLL);
            if self.child.try_wait().unwrap().is_some() {
                self.fail(&format!("verb exited before creating {}", path.display()));
            }
        }
        self.fail(&format!("verb never created {}", path.display()));
    }

    /// Send `signal` to the child, require a normal exit 0 inside the
    /// deadline, and return the full log.
    fn signal_and_expect_clean_exit(mut self, name: &str, signal: libc::c_int) -> (String, Self) {
        use std::os::unix::process::ExitStatusExt;

        // SAFETY: the pid is this test's own, still-owned child.
        unsafe {
            libc::kill(i32::try_from(self.child.id()).unwrap(), signal);
        }
        let deadline = Instant::now() + VERB_WAIT_DEADLINE;
        let status = loop {
            if Instant::now() > deadline {
                self.fail(&format!("{name}: verb did not exit after the signal"));
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            self.pump(VERB_POLL);
        };
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        while let Ok(line) = self.rx.try_recv() {
            self.log.push_str(&line);
            self.log.push('\n');
        }
        assert_eq!(
            status.signal(),
            None,
            "{name}: died by signal:\n{}",
            self.log
        );
        assert!(status.success(), "{name}: exit {status:?}:\n{}", self.log);
        (std::mem::take(&mut self.log), self)
    }
}

/// A panic outside `fail()` (an assert before the signal, an `unwrap` on
/// `try_wait`) must not leak the spawned daemon: kill and reap this test's
/// own child (a no-op error when it already exited).
#[cfg(unix)]
impl Drop for Verb {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `sync-daemon` takes SIGINT and SIGTERM down the same graceful path (exit 0).
#[cfg(unix)]
#[test]
fn sync_daemon_stop_signals_exit_zero_8193() {
    for (name, signal) in STOP_SIGNALS {
        let mut verb = Verb::spawn(&["sync-daemon", "--peers", SYNC_UNREACHABLE_PEER]);
        verb.wait_for_log(SYNC_BOOT_MARKER);
        std::thread::sleep(VERB_SETTLE);
        let _ = verb.signal_and_expect_clean_exit(name, signal);
    }
}

/// `wake-hub` under a real SIGINT / SIGTERM: drains, exits 0, and unlinks the
/// socket it created.
#[cfg(unix)]
#[test]
fn wake_hub_stop_signals_exit_zero_and_unlink_the_socket_8193() {
    for (name, signal) in STOP_SIGNALS {
        // The socket path must stay short (AF_UNIX limit): a dedicated temp
        // dir, alive for the whole iteration.
        let sock_dir = tempfile::TempDir::new().unwrap();
        // The hub refuses a socket directory that is not owner-only.
        std::fs::set_permissions(
            sock_dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let socket = sock_dir.path().join("hub.sock");
        let socket_arg = socket.to_str().unwrap().to_owned();
        let mut verb = Verb::spawn(&["wake-hub", "--socket", &socket_arg]);
        verb.wait_for_log(WAKE_HUB_BOOT_MARKER);
        assert!(socket.exists(), "{name}: the hub must own its socket");
        std::thread::sleep(VERB_SETTLE);
        let (log, _verb) = verb.signal_and_expect_clean_exit(name, signal);
        assert!(
            log.contains(WAKE_HUB_STOPPED_MARKER),
            "{name}: the hub must log its drain:\n{log}"
        );
        assert!(
            !socket.exists(),
            "{name}: the hub must unlink the socket it created"
        );
    }
}

/// `watch --daemon` under a real SIGINT / SIGTERM: the loop stops between
/// ticks and the process exits 0.
#[cfg(unix)]
#[test]
fn watch_daemon_stop_signals_exit_zero_8193() {
    for (name, signal) in STOP_SIGNALS {
        let mut verb = Verb::spawn(&["watch", "--daemon", "--interval-secs", "1"]);
        verb.wait_for_log(WATCH_BOOT_MARKER);
        std::thread::sleep(VERB_SETTLE);
        let (log, _verb) = verb.signal_and_expect_clean_exit(name, signal);
        assert!(
            log.contains(WATCH_STOPPED_MARKER),
            "{name}: the watch loop must log its shutdown:\n{log}"
        );
    }
}

/// `curator --daemon` under a real SIGINT / SIGTERM exits 0.
#[cfg(unix)]
#[test]
fn curator_daemon_stop_signals_exit_zero_8193() {
    for (name, signal) in STOP_SIGNALS {
        let mut verb = Verb::spawn(&["curator", "--daemon", "--interval-secs", "3600"]);
        verb.wait_for_log(CURATOR_BOOT_MARKER);
        std::thread::sleep(VERB_SETTLE);
        let _ = verb.signal_and_expect_clean_exit(name, signal);
    }
}

/// #8193 N1: the curator installs its listener before spawning the waiter,
/// so a stop signal sent the moment the daemon reports it started (no settle
/// pause) still takes the drained exit 0, never the default disposition.
#[cfg(unix)]
#[test]
fn curator_daemon_early_stop_signals_exit_zero_8193() {
    for (name, signal) in STOP_SIGNALS {
        let mut verb = Verb::spawn(&["curator", "--daemon", "--interval-secs", "3600"]);
        verb.wait_for_log(CURATOR_BOOT_MARKER);
        let _ = verb.signal_and_expect_clean_exit(name, signal);
    }
}

/// M1 of the r1 review: a stop signal delivered while a slow `--exec` hook is
/// running must not be lost. The listener finishes (and reaps) the hook, sees
/// the signal, and exits 0 inside the deadline; it never runs on until SIGKILL.
#[cfg(unix)]
#[test]
fn wake_listen_stop_signal_during_a_slow_exec_hook_exits_zero_8193() {
    for (name, signal) in STOP_SIGNALS {
        let tmp = tempfile::TempDir::new().unwrap();
        let started = tmp.path().join("hook-started");
        let done = tmp.path().join("hook-done");
        let hook = format!(
            "touch {started}; sleep {HOOK_SLEEP_SECS}; touch {done}",
            started = started.display(),
            done = done.display()
        );
        let key_dir = tmp.path().join("no-keys");
        let mut verb = Verb::spawn(&[
            "wake-listen",
            "--agent-id",
            "ai:listener-8193",
            "--no-hub",
            "--poll-secs",
            "1",
            "--key-dir",
            key_dir.to_str().unwrap(),
            "--exec",
            &hook,
        ]);
        verb.wait_for_log(WAKE_LISTEN_BOOT_MARKER);
        // The signal arrives while the hook is running: the window in which
        // the pre-fix listener (one listener per loop iteration) had none.
        verb.wait_for_file(&started);
        let (log, _verb) = verb.signal_and_expect_clean_exit(name, signal);
        assert!(
            log.contains(WAKE_LISTEN_STOPPING_MARKER),
            "{name}: the listener must log that it stopped on the signal:\n{log}"
        );
        assert!(
            done.exists(),
            "{name}: the in-flight hook must run to completion and be reaped"
        );
        drop(tmp);
    }
}
