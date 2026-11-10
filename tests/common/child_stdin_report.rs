// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Shared stdin writer for test helpers that drive a spawned child (#8734).
//!
//! RED-COMMIT STUB: this file reproduces today's behaviour (a failed write
//! panics with the bare io error, the child is not reaped, its exit status
//! and stderr are lost). The next commit replaces it with the real helper.

#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::process::{Child, ChildStdin};
use std::time::Duration;

pub const CHILD_REAP_BOUND: Duration = Duration::from_secs(10);
pub const STDERR_REPORT_MAX_BYTES: usize = 8 * 1024;
pub const STDERR_TRUNCATION_MARKER_PREFIX: &str = "[child stderr truncated at ";
pub const WRITE_FAILED_PREFIX: &str = "child stdin write failed (";
pub const EXIT_LINE_EXITED: &str = "child exit: exited with ";
pub const EXIT_LINE_KILLED: &str = "child exit: still running after ";
pub const STDERR_HEADER: &str = "child stderr:";
pub const STDERR_NOT_CAPTURED: &str = "<not captured: the child's stderr is not piped to the test>";

/// Stub: reads nothing.
pub struct StderrCapture;

impl StderrCapture {
    #[must_use]
    pub fn drain(_stderr: impl Read + Send + 'static) -> Self {
        Self
    }
}

/// Stub: the bare io error, as `expect("request")` printed it.
pub fn child_write_failure_message(
    _child: &mut Child,
    _stderr: Option<&StderrCapture>,
    _what: &str,
    err: &io::Error,
    _bound: Duration,
) -> String {
    format!("request: {err:?}")
}

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

pub fn send_and_close(child: &mut Child, what: &str, payload: &[u8]) {
    let mut stdin = child.stdin.take().expect("stdin");
    if let Err(err) = stdin.write_all(payload).and_then(|()| stdin.flush()) {
        report_child_write_failure(child, None, what, &err);
    }
}

pub fn write_open(child: &mut Child, what: &str, payload: &[u8]) {
    let stdin = child.stdin.as_mut().expect("stdin");
    if let Err(err) = stdin.write_all(payload).and_then(|()| stdin.flush()) {
        report_child_write_failure(child, None, what, &err);
    }
}

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
