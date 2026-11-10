// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared stdin writer for test helpers that drive a spawned child (#8734).
//!
//! A test that writes a request to a child's stdin and panics on the write
//! error (`expect`, `unwrap`) reports an early child exit as a bare
//! `Os { code: 32, kind: BrokenPipe }`: the panic fires before the child is
//! reaped, so its exit status and stderr, which say WHY it exited, are lost.
//! The helpers here turn any failed write or flush into one fixed-format
//! failure that has reaped the child within [`CHILD_REAP_BOUND`] and carries
//! its exit status and its stderr (cut at [`STDERR_REPORT_MAX_BYTES`]).
//!
//! A successful write changes nothing: no retry, no extra wait, no changed
//! assertion.
//!
//! ## Message format (fixed parts are pinned by `child_stdin_write_report_8734`)
//!
//! ```text
//! child stdin write failed (<what>): <io error>
//! child exit: exited with <status>
//!   (or) child exit: still running after <n>ms; killed, then exited with <status>
//! child stderr:
//! <stderr text>
//! [child stderr truncated at <n> bytes]      (only when it was cut)
//! ```
//!
//! ## Usage
//!
//! A LEAF helper (`std` only), pulled in through the `#[path]` idiom the MCP
//! suites already use for `mcp_wait`:
//!
//! ```ignore
//! #[path = "common/child_stdin_report.rs"]
//! mod child_stdin_report;
//! ```

#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::process::{Child, ChildStdin, ExitStatus};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long a child whose stdin write failed is given to exit by itself
/// before it is killed and reaped.
pub const CHILD_REAP_BOUND: Duration = Duration::from_secs(10);
/// Poll step while waiting for the child to exit.
const REAP_POLL: Duration = Duration::from_millis(10);
/// How long the stderr reader is given, after the child is reaped, to reach
/// end of file (a grandchild that inherited the pipe can keep it open).
const STDERR_JOIN_BOUND: Duration = Duration::from_secs(2);
/// Chunk size of the stderr reader.
const STDERR_CHUNK_BYTES: usize = 4096;
/// Most stderr bytes a failure message carries.
pub const STDERR_REPORT_MAX_BYTES: usize = 8 * 1024;
/// Marker line appended when stderr was longer than the bound.
pub const STDERR_TRUNCATION_MARKER_PREFIX: &str = "[child stderr truncated at ";
/// First line prefix of every failure message.
pub const WRITE_FAILED_PREFIX: &str = "child stdin write failed (";
/// Exit line prefix for a child that had already exited.
pub const EXIT_LINE_EXITED: &str = "child exit: exited with ";
/// Exit line prefix for a child that had to be killed.
pub const EXIT_LINE_KILLED: &str = "child exit: still running after ";
/// Header line of the stderr section.
pub const STDERR_HEADER: &str = "child stderr:";
/// Stderr text when the helper was given no way to read it.
pub const STDERR_NOT_CAPTURED: &str = "<not captured: the child's stderr is not piped to the test>";

#[derive(Default)]
struct Captured {
    bytes: Vec<u8>,
    truncated: bool,
}

/// A background reader that drains a child's stderr for the whole life of the
/// child and keeps the first [`STDERR_REPORT_MAX_BYTES`] bytes, so a failure
/// message can quote them. Replaces the "drain and discard" thread.
pub struct StderrCapture {
    shared: Arc<Mutex<Captured>>,
    reader: Mutex<Option<JoinHandle<()>>>,
}

impl StderrCapture {
    /// Start draining `stderr`.
    #[must_use]
    pub fn drain(mut stderr: impl Read + Send + 'static) -> Self {
        let shared = Arc::new(Mutex::new(Captured::default()));
        let sink = Arc::clone(&shared);
        let reader = std::thread::spawn(move || {
            let mut chunk = [0u8; STDERR_CHUNK_BYTES];
            while let Ok(n) = stderr.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let mut held = sink.lock().unwrap_or_else(PoisonError::into_inner);
                let room = STDERR_REPORT_MAX_BYTES.saturating_sub(held.bytes.len());
                let keep = n.min(room);
                held.bytes.extend_from_slice(&chunk[..keep]);
                if keep < n {
                    held.truncated = true;
                }
            }
        });
        Self {
            shared,
            reader: Mutex::new(Some(reader)),
        }
    }

    /// The captured text and whether it was cut. Waits up to
    /// [`STDERR_JOIN_BOUND`] for the reader to reach end of file (call it
    /// after the child is reaped).
    fn collect(&self) -> (String, bool) {
        let handle = self
            .reader
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(handle) = handle {
            finish_reader(handle);
        }
        let held = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        (
            String::from_utf8_lossy(&held.bytes).into_owned(),
            held.truncated,
        )
    }
}

/// Wait up to `bound` for the child to exit, then kill it, and reap it.
/// Returns its status and whether it had to be killed.
fn reap_within(child: &mut Child, bound: Duration) -> (ExitStatus, bool) {
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return (status, false),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(REAP_POLL),
            Ok(None) | Err(_) => break,
        }
    }
    let _ = child.kill();
    let status = child.wait().expect("reap the child that was killed");
    (status, true)
}

/// Wait up to [`STDERR_JOIN_BOUND`] for a stderr reader thread the caller owns
/// to reach end of file, and join it when it did (call it after the child is
/// reaped).
pub fn finish_reader(handle: JoinHandle<()>) {
    let deadline = Instant::now() + STDERR_JOIN_BOUND;
    while !handle.is_finished() && Instant::now() < deadline {
        std::thread::sleep(REAP_POLL);
    }
    if handle.is_finished() {
        let _ = handle.join();
    }
}

/// Cut `text` to [`STDERR_REPORT_MAX_BYTES`] bytes (lossily at the byte
/// boundary, so a split character shows as U+FFFD) and say whether it was cut.
fn bound_text(text: &str) -> (String, bool) {
    let bytes = text.as_bytes();
    if bytes.len() <= STDERR_REPORT_MAX_BYTES {
        return (text.to_owned(), false);
    }
    (
        String::from_utf8_lossy(&bytes[..STDERR_REPORT_MAX_BYTES]).into_owned(),
        true,
    )
}

/// The failure message once the child is reaped: headline, exit line, stderr.
fn render(
    what: &str,
    err: &io::Error,
    status: ExitStatus,
    killed: bool,
    bound: Duration,
    stderr: (String, bool),
) -> String {
    let exit_line = if killed {
        format!(
            "{EXIT_LINE_KILLED}{}ms; killed, then exited with {status}",
            bound.as_millis()
        )
    } else {
        format!("{EXIT_LINE_EXITED}{status}")
    };
    let (text, truncated) = stderr;
    let mut message =
        format!("{WRITE_FAILED_PREFIX}{what}): {err}\n{exit_line}\n{STDERR_HEADER}\n{text}");
    if truncated {
        message =
            format!("{message}\n{STDERR_TRUNCATION_MARKER_PREFIX}{STDERR_REPORT_MAX_BYTES} bytes]");
    }
    message
}

/// Build the failure message for a failed write to `child`'s stdin: reaps the
/// child within `bound` (killing it when it is still running) and quotes its
/// exit status and stderr. `stderr` is a capture the caller already drains;
/// with `None` the child's own piped stderr is read here.
pub fn child_write_failure_message(
    child: &mut Child,
    stderr: Option<&StderrCapture>,
    what: &str,
    err: &io::Error,
    bound: Duration,
) -> String {
    drop(child.stdin.take());
    let owned = if stderr.is_none() {
        child.stderr.take().map(StderrCapture::drain)
    } else {
        None
    };
    let (status, killed) = reap_within(child, bound);
    let text = stderr.or(owned.as_ref()).map_or_else(
        || (STDERR_NOT_CAPTURED.to_owned(), false),
        StderrCapture::collect,
    );
    render(what, err, status, killed, bound, text)
}

/// Like [`child_write_failure_message`] for a caller that keeps the child's
/// stderr in its own buffer: `collect_stderr` runs AFTER the child is reaped
/// and returns everything captured so far (cut here at
/// [`STDERR_REPORT_MAX_BYTES`]).
pub fn child_write_failure_message_with(
    child: &mut Child,
    collect_stderr: impl FnOnce() -> String,
    what: &str,
    err: &io::Error,
    bound: Duration,
) -> String {
    drop(child.stdin.take());
    let (status, killed) = reap_within(child, bound);
    let text = bound_text(&collect_stderr());
    render(what, err, status, killed, bound, text)
}

/// Fail the test with [`child_write_failure_message`].
pub fn report_child_write_failure(
    child: &mut Child,
    stderr: Option<&StderrCapture>,
    what: &str,
    err: &io::Error,
) -> ! {
    panic!(
        "{}",
        child_write_failure_message(child, stderr, what, err, CHILD_REAP_BOUND)
    );
}

/// Write `payload` to the child's stdin, flush, and close stdin (the child
/// sees end of input). A failure reaps the child and fails with its status
/// and stderr.
pub fn send_and_close(child: &mut Child, what: &str, payload: &[u8]) {
    let Some(mut stdin) = child.stdin.take() else {
        panic!("{what}: the child's stdin is not piped");
    };
    if let Err(err) = stdin.write_all(payload).and_then(|()| stdin.flush()) {
        drop(stdin);
        report_child_write_failure(child, None, what, &err);
    }
}

/// Write `payload` to the child's stdin and flush; stdin stays open.
pub fn write_open(child: &mut Child, what: &str, payload: &[u8]) {
    let result = match child.stdin.as_mut() {
        Some(stdin) => stdin.write_all(payload).and_then(|()| stdin.flush()),
        None => panic!("{what}: the child's stdin is not piped"),
    };
    if let Err(err) = result {
        report_child_write_failure(child, None, what, &err);
    }
}

/// Write `line` and a newline to a stdin handle that was taken out of
/// `child`, then flush. A failure at the write or the flush reaps `child` and
/// fails with its status and stderr (`stderr` when the caller drains it
/// through a [`StderrCapture`]).
pub fn write_line_or_report(
    stdin: &mut ChildStdin,
    child: &mut Child,
    stderr: Option<&StderrCapture>,
    what: &str,
    line: &str,
) {
    let result = stdin
        .write_all(line.as_bytes())
        .and_then(|()| stdin.write_all(b"\n"))
        .and_then(|()| stdin.flush());
    if let Err(err) = result {
        report_child_write_failure(child, stderr, what, &err);
    }
}

/// [`write_line_or_report`] for a caller that keeps the child's stderr in its
/// own buffer (see [`child_write_failure_message_with`]).
pub fn write_line_or_report_with(
    stdin: &mut ChildStdin,
    child: &mut Child,
    collect_stderr: impl FnOnce() -> String,
    what: &str,
    line: &str,
) {
    let result = stdin
        .write_all(line.as_bytes())
        .and_then(|()| stdin.write_all(b"\n"))
        .and_then(|()| stdin.flush());
    if let Err(err) = result {
        panic!(
            "{}",
            child_write_failure_message_with(child, collect_stderr, what, &err, CHILD_REAP_BOUND)
        );
    }
}
