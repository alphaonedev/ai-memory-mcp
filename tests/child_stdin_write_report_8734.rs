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
    child_write_failure_message, child_write_failure_message_with, finish_reader, send_and_close,
    write_line_or_report, write_line_or_report_with,
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
    assert_eq!(output.stderr, Vec::<u8>::new());
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

// Row (f): a caller that keeps stderr in its own buffer.

#[test]
fn caller_buffer_stderr_is_quoted_and_cut_at_the_bound_8734() {
    let mut child = early_exit_child();
    let err = write_error(&mut child);
    let long = "y".repeat(STDERR_REPORT_MAX_BYTES + 100);
    let message =
        child_write_failure_message_with(&mut child, || long.clone(), WHAT, &err, GENEROUS_BOUND);
    let marker = format!("{STDERR_TRUNCATION_MARKER_PREFIX}{STDERR_REPORT_MAX_BYTES} bytes]");
    let (shown, tail) = stderr_section(&message)
        .split_once('\n')
        .expect("marker follows the stderr text");
    assert_eq!(shown.len(), STDERR_REPORT_MAX_BYTES);
    assert_eq!(tail, marker);
    assert!(
        message.contains(&format!("{EXIT_LINE_EXITED}exit status: {EARLY_EXIT_CODE}")),
        "{message}"
    );
}

#[test]
fn write_line_or_report_with_runs_the_collector_after_the_reap_8734() {
    let mut child = early_exit_child();
    let mut stdin = child.stdin.take().expect("piped stdin");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        write_line_or_report_with(
            &mut stdin,
            &mut child,
            || {
                let mut text = String::new();
                stderr_pipe.read_to_string(&mut text).expect("read stderr");
                text
            },
            WHAT,
            PAYLOAD,
        );
    }));
    let payload = outcome.expect_err("a write to a gone child must fail the caller");
    let message = payload.downcast_ref::<String>().cloned().expect("String");
    assert_eq!(stderr_section(&message), format!("{EARLY_STDERR}\n"));
}

#[test]
fn finish_reader_returns_within_its_bound_when_the_pipe_stays_open_8734() {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let _ = rx.recv();
    });
    let started = Instant::now();
    finish_reader(handle);
    assert!(
        started.elapsed() < KILL_CEILING,
        "took {:?}",
        started.elapsed()
    );
    drop(tx);
}

// Guard (#8734, class fix): no new unconverted child-stdin write.
//
// A source scan over every `.rs` file under `tests/` and `benches/`. It fails,
// naming `file:line`, on a child-stdin handle access (`<x>.stdin.take()`,
// `.stdin.as_mut()`, `.stdin.as_ref()` and every other `.stdin` field form;
// the `.stdin(Stdio::piped())` builder call is not an access) whose handle is
// written to directly, in the same statement or through the name the access is
// bound to, outside the helper modules. A handle that is handed to
// `child_stdin_report`, or only dropped to close stdin, is not a write.
//
// Sites are matched on file plus a stable text anchor, never a bare line
// number, so an unrelated edit does not break the guard.

/// A file the scan never reports, with the reason.
struct ExemptFile {
    path: &'static str,
    reason: &'static str,
}

/// Files outside the scan: the helper module and this binary.
const GUARD_EXEMPT_FILES: &[ExemptFile] = &[
    ExemptFile {
        path: "tests/common/child_stdin_report.rs",
        reason: "the helper itself: its raw writes are the one reviewed implementation",
    },
    ExemptFile {
        path: "tests/child_stdin_write_report_8734.rs",
        reason: "this binary: its fixtures write raw on purpose to produce the failures the \
                 helper must report, and its synthetic sources hold the text the scan looks for",
    },
];

/// One allowlisted site group: every flagged site in `file` whose line text
/// contains `anchor`. `sites` is the exact number of such sites, so an entry
/// whose site vanished (or a second site that appeared) fails the guard.
struct AllowEntry {
    file: &'static str,
    anchor: &'static str,
    sites: usize,
    reason: &'static str,
}

/// The ONE allowlist of child-stdin writes that stay raw.
const STDIN_WRITE_ALLOWLIST: &[AllowEntry] = &[
    AllowEntry {
        file: "tests/mcp_signal_drain_4347.rs",
        anchor: "if let Some(mut stdin) = child.stdin.take()",
        sites: 1,
        reason: "deliberate `let _ = writeln!` to a child that is expected to have exited \
                 (a failed write is the refusal the test asserts)",
    },
    AllowEntry {
        file: "tests/mcp_signal_drain_4347.rs",
        anchor: "let mut stdin = child.stdin.take().expect(\"stdin\");",
        sites: 1,
        reason: "burst writer thread whose write results are discarded with `let _` on \
                 purpose: the child is cut by SIGTERM mid-burst",
    },
];

/// A flagged child-stdin access.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Site {
    file: String,
    line: usize,
    text: String,
}

/// Tokens that write to a handle.
const WRITE_TOKENS: &[&str] = &[
    "write_all(",
    "write!(",
    "writeln!(",
    ".write(",
    ".flush(",
    "write_fmt(",
];

/// Pattern keywords that are not binding names.
const PATTERN_KEYWORDS: &[&str] = &["let", "if", "while", "Some", "Ok", "mut", "ref", "else"];

/// How far past an access a bound name is followed (lines).
const FOLLOW_LINES: usize = 40;

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `source` with every whole-line `//` comment blanked, byte offsets kept.
fn blank_comment_lines(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.split_inclusive('\n') {
        if line.trim_start().starts_with("//") {
            out.extend(line.chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
        } else {
            out.push_str(line);
        }
    }
    out
}

/// Byte offsets of every `;`, `{` and `}` outside a string or char literal.
fn statement_boundaries(source: &str) -> Vec<usize> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'\'' => {
                // A char literal ('x' or '\n'); a lifetime has no closing quote.
                let close = if bytes.get(i + 1) == Some(&b'\\') { i + 3 } else { i + 2 };
                if bytes.get(close) == Some(&b'\'') {
                    i = close;
                }
            }
            b';' | b'{' | b'}' => out.push(i),
            _ => {}
        }
        i += 1;
    }
    out
}

/// Byte offsets of every child-stdin field access in `source`: `.stdin`
/// followed by neither an identifier character nor `(`.
fn stdin_accesses(source: &str) -> Vec<usize> {
    const NEEDLE: &str = ".stdin";
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(found) = source[from..].find(NEEDLE) {
        let at = from + found;
        let after = source[at + NEEDLE.len()..].chars().next();
        if after.is_none_or(|c| !is_ident_char(c) && c != '(') {
            out.push(at);
        }
        from = at + NEEDLE.len();
    }
    out
}

/// Identifiers a `let` / `if let` / `while let` statement binds.
fn bound_names(statement: &str) -> Vec<String> {
    let trimmed = statement.trim_start();
    if !(trimmed.starts_with("let ")
        || trimmed.starts_with("if let ")
        || trimmed.starts_with("while let "))
    {
        return Vec::new();
    }
    let pattern = trimmed.split_once('=').map_or(trimmed, |(left, _)| left);
    let mut names = Vec::new();
    let mut word = String::new();
    for c in pattern.chars().chain(std::iter::once(' ')) {
        if is_ident_char(c) {
            word.push(c);
        } else {
            if !word.is_empty()
                && word != "_"
                && !PATTERN_KEYWORDS.contains(&word.as_str())
                && !word.starts_with(|first: char| first.is_ascii_digit())
            {
                names.push(word.clone());
            }
            word.clear();
        }
    }
    names
}

/// Whether `region` writes to the binding `name`.
fn writes_to_name(region: &str, name: &str) -> bool {
    let macro_forms = [
        format!("write!({name}"),
        format!("writeln!({name}"),
        format!("write!(&mut {name}"),
        format!("writeln!(&mut {name}"),
    ];
    if macro_forms.iter().any(|form| region.contains(form)) {
        return true;
    }
    [".write_all(", ".write(", ".flush(", ".write_fmt("]
        .iter()
        .any(|method| {
            let needle = format!("{name}{method}");
            region.match_indices(&needle).any(|(at, _)| {
                !region[..at]
                    .chars()
                    .next_back()
                    .is_some_and(is_ident_char)
            })
        })
}

/// The text after `end` up to the end of the enclosing function (or
/// [`FOLLOW_LINES`] lines).
fn following_region(source: &str, end: usize) -> &str {
    let rest = &source[end..];
    let mut offset = 0;
    for (n, line) in rest.split_inclusive('\n').enumerate() {
        let starts_item = line.starts_with("fn ")
            || line.starts_with("pub fn ")
            || line.starts_with("#[test]")
            || line.starts_with('}');
        if n > 0 && (starts_item || n > FOLLOW_LINES) {
            break;
        }
        offset += line.len();
    }
    &rest[..offset]
}

/// STUB (red commit): reports nothing, so the rows that need a flagged site fail.
fn scan_source(_file: &str, _source: &str) -> Vec<Site> {
    Vec::new()
}

/// Sites no allowlist entry covers, and the entries whose site count is not
/// the number of sites they match (stale or grown).
fn unallowed_and_stale<'a>(
    sites: &[Site],
    allow: &'a [AllowEntry],
) -> (Vec<Site>, Vec<&'a AllowEntry>) {
    let covers = |entry: &AllowEntry, site: &Site| {
        site.file == entry.file && site.text.contains(entry.anchor)
    };
    let unallowed = sites
        .iter()
        .filter(|site| !allow.iter().any(|entry| covers(entry, site)))
        .cloned()
        .collect();
    let stale = allow
        .iter()
        .filter(|entry| sites.iter().filter(|site| covers(entry, site)).count() != entry.sites)
        .collect();
    (unallowed, stale)
}

/// Every `.rs` file under `dir`, recursively, sorted.
fn rust_files_under(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            rust_files_under(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The scan over the real tree.
fn scan_tree() -> Vec<Site> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in ["tests", "benches"] {
        rust_files_under(&root.join(dir), &mut files);
    }
    let mut sites = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .expect("under the manifest dir")
            .to_string_lossy()
            .replace('\\', "/");
        if GUARD_EXEMPT_FILES.iter().any(|exempt| exempt.path == relative) {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read a test source");
        sites.extend(scan_source(&relative, &source));
    }
    sites
}

/// The failure text for a violation, naming `file:line`.
fn describe(site: &Site) -> String {
    format!("{}:{}: {}", site.file, site.line, site.text)
}

/// A scratch test file with an unconverted write, built without the text the
/// scan looks for appearing in this file's own scan (this file is exempt).
const UNCONVERTED_SOURCE: &str = "fn drive() {\n    let mut child = spawn();\n    \
    writeln!(child.stdin.take().expect(\"stdin\"), \"{request}\").expect(\"request\");\n}\n";

/// The same write after conversion to the helper.
const CONVERTED_SOURCE: &str = "fn drive() {\n    let mut child = spawn();\n    \
    child_stdin_report::send_and_close(&mut child, \"request\", b\"x\");\n}\n";

/// The bound-name form: take, bind, write through the name.
const BOUND_SOURCE: &str = "fn drive() {\n    let mut stdin = child.stdin.take().unwrap();\n    \
    stdin.write_all(b\"x\").unwrap();\n}\n";

/// The `as_mut` form on a field.
const AS_MUT_SOURCE: &str = "fn drive(&mut self) {\n    let stdin = self.stdin.as_mut().unwrap();\n    \
    stdin.flush().unwrap();\n}\n";

/// A source whose only stdin use is closing it or the builder call.
const NON_WRITE_SOURCE: &str = "fn drive() {\n    let child = Command::new(\"x\").stdin(Stdio::piped()).spawn();\n    \
    drop(child.stdin.take());\n    // child.stdin.take() in a comment: ignored\n}\n";

// Row (g1): an unconverted write is flagged with its line.

#[test]
fn guard_flags_an_unconverted_write_with_its_line_8734() {
    let sites = scan_source("tests/scratch_8734.rs", UNCONVERTED_SOURCE);
    assert_eq!(sites.len(), 1, "{sites:?}");
    assert_eq!(describe(&sites[0]).split(':').take(2).collect::<Vec<_>>(), [
        "tests/scratch_8734.rs",
        "3"
    ]);
    let (violations, stale) = unallowed_and_stale(&sites, &[]);
    assert_eq!(violations, sites, "no allowlist entry: it is a violation");
    assert!(stale.is_empty());
    for (name, source) in [("bound", BOUND_SOURCE), ("as_mut", AS_MUT_SOURCE)] {
        let found = scan_source("tests/scratch_8734.rs", source);
        assert_eq!(found.len(), 1, "{name} form: {found:?}");
        assert_eq!(found[0].line, 2, "{name} form reports the access line");
    }
    for (name, source) in [
        ("converted", CONVERTED_SOURCE),
        ("close and builder", NON_WRITE_SOURCE),
    ] {
        assert!(
            scan_source("tests/scratch_8734.rs", source).is_empty(),
            "{name} form is not a write"
        );
    }
}

// Row (g2): a synthetic allowlisted site passes.

#[test]
fn guard_passes_an_allowlisted_site_8734() {
    let sites = scan_source("tests/scratch_8734.rs", UNCONVERTED_SOURCE);
    let allow = [AllowEntry {
        file: "tests/scratch_8734.rs",
        anchor: "child.stdin.take().expect(\"stdin\")",
        sites: 1,
        reason: "synthetic",
    }];
    let (violations, stale) = unallowed_and_stale(&sites, &allow);
    assert!(violations.is_empty(), "{violations:?}");
    assert!(stale.is_empty());
}

// Row (g3): an allowlist entry whose site no longer exists fails.

#[test]
fn guard_fails_a_stale_allowlist_entry_8734() {
    let sites = scan_source("tests/scratch_8734.rs", CONVERTED_SOURCE);
    let allow = [AllowEntry {
        file: "tests/scratch_8734.rs",
        anchor: "child.stdin.take().expect(\"stdin\")",
        sites: 1,
        reason: "synthetic",
    }];
    let (violations, stale) = unallowed_and_stale(&sites, &allow);
    assert!(violations.is_empty());
    assert_eq!(stale.len(), 1, "the entry has no site left");
    // A second matching site than the entry names fails the same way.
    let doubled = scan_source(
        "tests/scratch_8734.rs",
        &format!("{UNCONVERTED_SOURCE}{UNCONVERTED_SOURCE}"),
    );
    let (_, grown) = unallowed_and_stale(&doubled, &allow);
    assert_eq!(grown.len(), 1, "a new site under an old entry fails");
}

// Row (g4): the real tree passes.

#[test]
fn every_child_stdin_write_in_tests_and_benches_goes_through_the_helper_8734() {
    let sites = scan_tree();
    let (violations, stale) = unallowed_and_stale(&sites, STDIN_WRITE_ALLOWLIST);
    let report: Vec<String> = violations.iter().map(describe).collect();
    assert!(
        violations.is_empty(),
        "unconverted child-stdin write(s); use tests/common/child_stdin_report.rs \
         (or add one allowlist entry with a reason):\n{}",
        report.join("\n")
    );
    let stale_report: Vec<String> = stale
        .iter()
        .map(|entry| format!("{} {:?} ({})", entry.file, entry.anchor, entry.reason))
        .collect();
    assert!(
        stale.is_empty(),
        "allowlist entries that match no site, or a different number than named:\n{}",
        stale_report.join("\n")
    );
}
