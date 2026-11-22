// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! One guard for every spawned `ai-memory` child of the drain cells (#9906 F1).
//!
//! The class: a test waits on a child, the wait fails (deadline, early exit,
//! failed write), and the failure neither stops the child nor says what the
//! child printed. A hung child then outlives the test binary and the cell
//! reports a bare count.
//!
//! The invariant, held by construction (TEST-02, ERRORS-24, OWNERSHIP-24):
//! every failure path of every wait on a child kills it, waits on it, and
//! panics with the child's stderr (cut at [`STDERR_REPORT_MAX_BYTES`]) and
//! the named deadline. The pieces:
//!
//! - [`ChildGuard`] owns the child and its stderr reader. `Drop` kills and
//!   waits a child that is still running, so a panic anywhere reaps it.
//! - [`ChildGuard::failure_text`] is the one place that builds the failure
//!   text; [`ChildGuard::fail`], [`ChildGuard::wait_exit_bounded`],
//!   [`ChildGuard::recv_line`], [`ChildGuard::write_line`] and
//!   [`ChildGuard::wait_stderr_contains`] all go through it.
//! - [`spawn_line_reader`] gives a child's stdout a bounded read (a channel),
//!   so no wait is a bare blocking `read_line`.
//! - [`requested_tiers`] reads the tier line the child printed, the pin of the
//!   `--tier` every spawn site passes (#9913).
//!
//! A LEAF helper (`std` only), pulled in through the `#[path]` idiom:
//!
//! ```ignore
//! #[path = "common/mcp_child_guard.rs"]
//! mod mcp_child_guard;
//! ```

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, ExitStatus};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Longest stderr tail a failure message quotes.
pub const STDERR_REPORT_MAX_BYTES: usize = 8 * 1024;

/// How long the stderr reader may take to reach end of file once the child is
/// reaped.
const STDERR_JOIN_BOUND: Duration = Duration::from_secs(2);

/// Poll interval of the bounded waits.
const WAIT_POLL: Duration = Duration::from_millis(10);

/// Prefix of the line `ai-memory mcp` writes with the tier it serves
/// (`src/mcp/mod.rs::run_mcp_server`).
pub const TIER_LINE: &str = "ai-memory: requested tier = ";

/// The tiers a child's stderr reports, in order (one per `TIER_LINE`).
pub fn requested_tiers(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter_map(|l| l.strip_prefix(TIER_LINE))
        .map(str::trim)
        .collect()
}

/// Owns a spawned child and the thread that drains its stderr.
pub struct ChildGuard {
    child: Child,
    stderr: Arc<Mutex<Vec<u8>>>,
    reader: Option<JoinHandle<()>>,
}

impl ChildGuard {
    /// Take over `child`; its piped stderr is drained on a thread from now on,
    /// so a full pipe can never stall it and the text is there on a failure.
    pub fn new(mut child: Child) -> Self {
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let reader = child.stderr.take().map(|mut pipe| {
            let sink = Arc::clone(&stderr);
            std::thread::spawn(move || {
                let mut chunk = [0_u8; 1024];
                while let Ok(n) = pipe.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    sink.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .extend_from_slice(&chunk[..n]);
                }
            })
        });
        Self {
            child,
            stderr,
            reader,
        }
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    /// Whether the child is still running (`try_wait` reports no status).
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// The child's stderr so far (lossy UTF-8).
    pub fn stderr_so_far(&self) -> String {
        let held = self.stderr.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&held).into_owned()
    }

    /// All of the child's stderr: waits (bounded) for the reader to reach end
    /// of file, so call it after the child exited.
    pub fn stderr_final(&mut self) -> String {
        self.finish_reader();
        self.stderr_so_far()
    }

    fn finish_reader(&mut self) {
        let Some(handle) = self.reader.take() else {
            return;
        };
        let deadline = Instant::now() + STDERR_JOIN_BOUND;
        while !handle.is_finished() && Instant::now() < deadline {
            std::thread::sleep(WAIT_POLL);
        }
        if handle.is_finished() {
            let _ = handle.join();
        } else {
            // A grandchild holds the pipe open: leave the thread, keep the
            // text read so far.
            self.reader = None;
        }
    }

    /// Kill the child when it is still running and wait on it. Returns its
    /// status and whether it had to be killed.
    pub fn reap(&mut self) -> (ExitStatus, bool) {
        let killed = self.is_running();
        if killed {
            let _ = self.child.kill();
        }
        // The child is dead or about to be (SIGKILL): this wait is bounded by
        // the kernel, and it reaps the pid.
        let status = self.child.wait().expect("reap the child");
        (status, killed)
    }

    /// The one failure text: the child is killed when still running and
    /// waited on, then the message names the wait (`what`), its deadline
    /// (`bound`, when it was a deadline), the exit status and the child's
    /// stderr cut at [`STDERR_REPORT_MAX_BYTES`].
    pub fn failure_text(&mut self, what: &str, bound: Option<Duration>) -> String {
        drop(self.child.stdin.take());
        let (status, killed) = self.reap();
        let stderr = self.stderr_final();
        let headline = match (killed, bound) {
            (true, Some(bound)) => {
                format!("no {what} within {bound:?}; the child was killed ({status:?})")
            }
            (true, None) => format!("the child was killed ({status:?}) while waiting for {what}"),
            (false, _) => format!("the child exited ({status:?}) while waiting for {what}"),
        };
        let (shown, cut) = cut_tail(&stderr);
        let note = if cut {
            format!("\n[stderr cut to its last {STDERR_REPORT_MAX_BYTES} bytes]")
        } else {
            String::new()
        };
        format!("{headline}; stderr:\n{shown}{note}")
    }

    /// Fail the test with [`Self::failure_text`].
    pub fn fail(&mut self, what: &str, bound: Option<Duration>) -> ! {
        panic!("{}", self.failure_text(what, bound));
    }

    /// Wait (bounded) for the child to exit; kills it and fails with its
    /// stderr and the deadline when it does not.
    pub fn wait_exit_bounded(&mut self, bound: Duration, what: &str) -> ExitStatus {
        let deadline = Instant::now() + bound;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return status,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(WAIT_POLL),
                Ok(None) | Err(_) => self.fail(what, Some(bound)),
            }
        }
    }

    /// Wait (bounded) until the child has written `needle` to stderr; fails
    /// at once, with the exit status and stderr, when the child exits first.
    pub fn wait_stderr_contains(&mut self, needle: &str, bound: Duration) {
        let deadline = Instant::now() + bound;
        loop {
            if self.stderr_so_far().contains(needle) {
                return;
            }
            if !self.is_running() {
                self.fail(&format!("{needle:?} on stderr"), None);
            }
            if Instant::now() >= deadline {
                self.fail(&format!("{needle:?} on stderr"), Some(bound));
            }
            std::thread::sleep(WAIT_POLL);
        }
    }

    /// Next stdout line from a [`spawn_line_reader`] channel, bounded. `None`
    /// at end of stream; a deadline kills the child and fails with its
    /// stderr.
    pub fn recv_line(
        &mut self,
        lines: &Receiver<String>,
        bound: Duration,
        what: &str,
    ) -> Option<String> {
        match lines.recv_timeout(bound) {
            Ok(line) => Some(line),
            Err(RecvTimeoutError::Disconnected) => None,
            Err(RecvTimeoutError::Timeout) => self.fail(what, Some(bound)),
        }
    }

    /// Write `line` and a newline to `stdin` and flush; a failed write kills
    /// and reaps the child and fails with its stderr.
    pub fn write_line(&mut self, stdin: &mut ChildStdin, what: &str, line: &str) {
        let result = stdin
            .write_all(line.as_bytes())
            .and_then(|()| stdin.write_all(b"\n"))
            .and_then(|()| stdin.flush());
        if let Err(err) = result {
            let text = self.failure_text(&format!("a write of {what} ({err})"), None);
            panic!("{text}");
        }
    }
}

impl Drop for ChildGuard {
    /// A child still running is killed and waited on; never panics
    /// (OWNERSHIP-25).
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        self.finish_reader();
    }
}

/// Read `stdout` line by line on a thread and forward each line; the channel
/// closes at end of stream.
pub fn spawn_line_reader(stdout: ChildStdout) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// `text` cut to its last [`STDERR_REPORT_MAX_BYTES`] bytes (lossily at the
/// byte boundary); whether it was cut.
fn cut_tail(text: &str) -> (String, bool) {
    let bytes = text.as_bytes();
    if bytes.len() <= STDERR_REPORT_MAX_BYTES {
        return (text.to_owned(), false);
    }
    let start = bytes.len() - STDERR_REPORT_MAX_BYTES;
    (String::from_utf8_lossy(&bytes[start..]).into_owned(), true)
}

/// Whether `pid` still names a process (a reaped child does not).
pub fn pid_exists(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: signal 0 only checks that the pid exists; no signal is sent.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}
