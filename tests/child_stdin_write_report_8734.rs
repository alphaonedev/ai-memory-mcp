// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8734 — a test helper that writes to a spawned child's stdin must not
//! hide why the child exited.
//!
//! Defect class: a helper spawns a child, writes a request to its stdin and
//! panics on the write error before it has reaped the child, so an early exit
//! is reported as `BrokenPipe` with no cause (red on docs-only PR #8705,
//! `archive_mcp_scope_3383`).
//!
//! Invariant: a failed write or flush (first or later write) reaps the child
//! within a named bound and fails with one fixed-format message that carries
//! the exit status and the child's stderr (cut at a named bound with a fixed
//! marker). A successful write changes nothing.

#![cfg(unix)]

#[path = "common/child_stdin_report.rs"]
mod child_stdin_report;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use child_stdin_report::{
    EXIT_LINE_EXITED, EXIT_LINE_KILLED, STDERR_HEADER, STDERR_REPORT_MAX_BYTES,
    STDERR_TRUNCATION_MARKER_PREFIX, StderrCapture, WRITE_FAILED_PREFIX,
    child_write_failure_message, send_and_close, write_line_or_report,
};

/// What the failing call site names itself.
const WHAT: &str = "request";
/// The text the early-exit fixture prints on stderr.
const EARLY_STDERR: &str = "fixture-8734: refusing to start: invalid database path";
/// The exit code of the early-exit fixture.
const EARLY_EXIT_CODE: i32 = 7;
/// The exit code of the fixture that reads one line and then exits.
const LATE_EXIT_CODE: i32 = 5;
/// The text the late-exit fixture prints on stderr.
const LATE_STDERR: &str = "fixture-8734: gave up after the first request";
/// Bound given to a child that closed stdin but keeps running.
const SHORT_BOUND: Duration = Duration::from_millis(200);
/// A kill-and-reap must finish well inside this wall-clock ceiling.
const KILL_CEILING: Duration = Duration::from_secs(5);
/// The payload every row writes.
const PAYLOAD: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";
/// A bound that no healthy child comes near.
const GENEROUS_BOUND: Duration = Duration::from_secs(30);

fn sh(script: &str) -> Child {
    Command::new("sh")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sh fixture")
}

/// Block until the fixture has exited and closed every descriptor, so the
/// next write to its stdin deterministically fails with `BrokenPipe`.
fn wait_until_closed(child: &mut Child) {
    let mut sink = Vec::new();
    child
        .stdout
        .as_mut()
        .expect("piped stdout")
        .read_to_end(&mut sink)
        .expect("read stdout to end of file");
}

fn early_exit_child() -> Child {
    let mut child = sh(&format!(
        "echo '{EARLY_STDERR}' >&2; exit {EARLY_EXIT_CODE}"
    ));
    wait_until_closed(&mut child);
    child
}

fn write_error(child: &mut Child) -> std::io::Error {
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(PAYLOAD.as_bytes())
        .expect_err("the child is gone, the write must fail")
}

/// The text between the stderr header line and the end of the message.
fn stderr_section(message: &str) -> &str {
    let header = format!("{STDERR_HEADER}\n");
    let at = message.find(&header).expect("stderr header present") + header.len();
    &message[at..]
}

// Row (a): the child exits before it reads.

#[test]
fn early_exit_failure_names_status_and_stderr_8734() {
    let mut child = early_exit_child();
    let err = write_error(&mut child);
    let message = child_write_failure_message(&mut child, None, WHAT, &err, GENEROUS_BOUND);
    let lines: Vec<&str> = message.lines().collect();
    assert_eq!(
        lines[0],
        format!("{WRITE_FAILED_PREFIX}{WHAT}): {err}"),
        "headline: {message}"
    );
    assert_eq!(
        lines[1],
        format!("{EXIT_LINE_EXITED}exit status: {EARLY_EXIT_CODE}"),
        "exit line: {message}"
    );
    assert_eq!(lines[2], STDERR_HEADER, "stderr header: {message}");
    assert_eq!(stderr_section(&message), format!("{EARLY_STDERR}\n"));
    assert!(
        child.try_wait().expect("poll").is_some(),
        "the child is reaped"
    );
}

#[test]
fn early_exit_through_send_and_close_panics_with_the_cause_8734() {
    let mut child = early_exit_child();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        send_and_close(&mut child, WHAT, PAYLOAD.as_bytes());
    }));
    let payload = outcome.expect_err("a write to a gone child must fail the caller");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .expect("panic carries a message");
    assert!(
        message.contains(&format!("{EXIT_LINE_EXITED}exit status: {EARLY_EXIT_CODE}")),
        "{message}"
    );
    assert!(message.contains(EARLY_STDERR), "{message}");
}

#[test]
fn early_exit_of_the_product_binary_names_its_stderr_8734() {
    // The #8734 shape itself: the product binary refuses an invalid `--db`
    // path and exits before it reads the request.
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .args(["--db", "/nonexistent-8734/dir/x.db", "mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the product binary");
    wait_until_closed(&mut child);
    let err = write_error(&mut child);
    let message = child_write_failure_message(&mut child, None, WHAT, &err, GENEROUS_BOUND);
    assert!(
        message.contains(&format!("{EXIT_LINE_EXITED}exit status: ")),
        "{message}"
    );
    assert!(
        !stderr_section(&message).trim().is_empty(),
        "the product's stderr is quoted: {message}"
    );
}

// Row (b): the child reads normally and the caller sees the same stdout.

#[test]
fn a_healthy_child_sees_the_same_bytes_8734() {
    let mut child = sh("cat");
    send_and_close(&mut child, WHAT, PAYLOAD.as_bytes());
    let output = child.wait_with_output().expect("collect output");
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), PAYLOAD);
    assert!(output.stderr.is_empty());
}

#[test]
fn a_healthy_child_answers_every_line_8734() {
    let mut child = sh("while read l; do echo \"echo:$l\"; done");
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    for n in 0..3 {
        let line = format!("{PAYLOAD}-{n}");
        write_line_or_report(&mut stdin, &mut child, None, WHAT, &line);
        let mut answer = String::new();
        stdout.read_line(&mut answer).expect("read answer");
        assert_eq!(answer, format!("echo:{line}\n"));
    }
    drop(stdin);
    assert!(child.wait().expect("reap").success());
}

// Row (c): the child closes stdin and keeps running.

#[test]
fn a_child_that_closed_stdin_and_keeps_running_is_killed_and_reaped_8734() {
    let mut child = sh("exec 0<&-; echo ready; exec sleep 60");
    let mut ready = String::new();
    BufReader::new(child.stdout.as_mut().expect("piped stdout"))
        .read_line(&mut ready)
        .expect("read the ready line");
    assert_eq!(ready, "ready\n");
    let err = write_error(&mut child);
    let started = Instant::now();
    let message = child_write_failure_message(&mut child, None, WHAT, &err, SHORT_BOUND);
    assert!(
        started.elapsed() < KILL_CEILING,
        "reaped within the ceiling, took {:?}",
        started.elapsed()
    );
    let expected = format!(
        "{EXIT_LINE_KILLED}{}ms; killed, then exited with ",
        SHORT_BOUND.as_millis()
    );
    assert!(message.contains(&expected), "{message}");
    assert!(
        child.try_wait().expect("poll").is_some(),
        "the killed child is reaped"
    );
}

// Row (d): stderr longer than the bound is cut with a fixed marker.

fn child_with_stderr_of(bytes: usize) -> Child {
    let mut child = sh(&format!(
        "head -c {bytes} /dev/zero | tr '\\0' x >&2; exit 3"
    ));
    wait_until_closed(&mut child);
    child
}

#[test]
fn stderr_longer_than_the_bound_is_cut_with_the_marker_8734() {
    let mut child = child_with_stderr_of(STDERR_REPORT_MAX_BYTES * 3 + 17);
    let err = write_error(&mut child);
    let message = child_write_failure_message(&mut child, None, WHAT, &err, GENEROUS_BOUND);
    let marker = format!("{STDERR_TRUNCATION_MARKER_PREFIX}{STDERR_REPORT_MAX_BYTES} bytes]");
    let section = stderr_section(&message);
    let (shown, tail) = section
        .split_once('\n')
        .expect("marker follows the stderr text");
    assert_eq!(shown.len(), STDERR_REPORT_MAX_BYTES);
    assert!(shown.bytes().all(|b| b == b'x'));
    assert_eq!(tail, marker);
}

#[test]
fn stderr_exactly_at_the_bound_is_not_marked_8734() {
    let mut child = child_with_stderr_of(STDERR_REPORT_MAX_BYTES);
    let err = write_error(&mut child);
    let message = child_write_failure_message(&mut child, None, WHAT, &err, GENEROUS_BOUND);
    let section = stderr_section(&message);
    assert_eq!(section.len(), STDERR_REPORT_MAX_BYTES);
    assert!(
        !message.contains(STDERR_TRUNCATION_MARKER_PREFIX),
        "{message}"
    );
}

// Row (e): a LATER write fails (the first one was accepted).

#[test]
fn a_later_write_failure_reports_the_cause_8734() {
    let mut child = sh(&format!(
        "read l; echo \"$l\"; echo '{LATE_STDERR}' >&2; exit {LATE_EXIT_CODE}"
    ));
    let mut stdin = child.stdin.take().expect("piped stdin");
    let capture = StderrCapture::drain(child.stderr.take().expect("piped stderr"));
    let mut stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
    write_line_or_report(&mut stdin, &mut child, Some(&capture), WHAT, PAYLOAD);
    let mut echoed = String::new();
    stdout.read_line(&mut echoed).expect("read echo");
    assert_eq!(echoed, format!("{PAYLOAD}\n"));
    let mut rest = Vec::new();
    stdout.read_to_end(&mut rest).expect("read to end of file");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        write_line_or_report(
            &mut stdin,
            &mut child,
            Some(&capture),
            "second request",
            PAYLOAD,
        );
    }));
    let payload = outcome.expect_err("the second write must fail the caller");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .expect("panic carries a String");
    assert!(
        message.starts_with(&format!("{WRITE_FAILED_PREFIX}second request): ")),
        "{message}"
    );
    assert!(
        message.contains(&format!("{EXIT_LINE_EXITED}exit status: {LATE_EXIT_CODE}")),
        "{message}"
    );
    assert_eq!(stderr_section(&message), format!("{LATE_STDERR}\n"));
}
