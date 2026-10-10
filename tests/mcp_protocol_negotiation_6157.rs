// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #6157: MCP `initialize` negotiates `protocolVersion` against the set of
//! revisions the server actually implements instead of echoing a hard-coded
//! string.
//!
//! Each cell drives a real `ai-memory mcp` child and asserts on BOTH the
//! wire result and the stderr diagnostic:
//!   * a client-requested revision the server supports is echoed back and
//!     produces no downgrade diagnostic;
//!   * an unsupported revision (including real, newer revisions whose
//!     deltas the server does not implement), a missing field and a
//!     non-string field all get the newest supported revision (the spec's
//!     "respond with another version you support") AND a stderr downgrade
//!     diagnostic, so an operator can see why a client was downgraded.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Duration;

use ai_memory::mcp::jsonrpc::{NEWEST_PROTOCOL_REVISION, protocol_downgrade_diagnostic};
use serde_json::{Value, json};

#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;
#[path = "common/mcp_wait.rs"]
mod mcp_wait;

/// The one revision the server implements end to end today (the SSOT pin in
/// `mcp_protocol_revision_ssot_6157.rs` proves this is a member of
/// `SUPPORTED_PROTOCOL_REVISIONS`).
const SHIPPED: &str = "2024-11-05";
/// A revision the server does not implement (kept off the `protocolVersion`
/// line so the SSOT pin only sees the supported literal).
const UNSUPPORTED: &str = "2099-01-01";
const WAIT: Duration = Duration::from_secs(60);

/// Send one `initialize` whose `params` is `params`; return the result's
/// `protocolVersion` and everything the child wrote to stderr.
fn initialize(params: &Value) -> (Value, String) {
    let fixture = mcp_stdio_child::Fixture::new();
    let mut child = fixture
        .command()
        .args(["mcp", "--profile", "full", "--tier", "keyword"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("MCP child");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Some(Ok(line)) = BufReader::new(stdout).lines().next() {
            let _ = tx.send(line);
        }
    });
    let request = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":params});
    writeln!(stdin, "{request}").expect("write initialize");
    stdin.flush().expect("flush");
    let line = rx.recv_timeout(WAIT).expect("initialize response");
    // EOF on stdin ends the server loop, so stderr reaches EOF too.
    drop(stdin);
    let mut diag = String::new();
    let _ = stderr.read_to_string(&mut diag);
    let _ = child.wait();
    let response: Value = serde_json::from_str(&line).expect("JSON-RPC response");
    assert!(
        response.get("error").is_none(),
        "initialize failed: {response}"
    );
    (response["result"]["protocolVersion"].clone(), diag)
}

#[test]
fn issue_6157_supported_revision_is_echoed_without_diagnostic() {
    let (version, diag) = initialize(&json!({"protocolVersion": SHIPPED, "capabilities": {}}));
    assert_eq!(version, SHIPPED);
    assert!(
        !diag.contains("protocolVersion"),
        "no downgrade diagnostic expected for a supported revision, got: {diag}"
    );
}

#[test]
fn issue_6157_unsupported_revision_gets_newest_supported_with_diagnostic() {
    // A made-up revision and the real newer revisions the server does not
    // implement all take the spec-mandated downgrade.
    for requested in [
        "2099-01-01",
        "2025-03-26",
        "2025-06-18",
        "2026-07-28",
        "latest",
        "",
    ] {
        let (version, diag) = initialize(&json!({"protocolVersion": requested}));
        assert_eq!(version, SHIPPED, "requested {requested:?}");
        assert!(
            diag.contains("protocolVersion") && diag.contains("downgrade"),
            "requested {requested:?}: missing stderr downgrade diagnostic, got: {diag}"
        );
    }
}

#[test]
fn issue_6157_missing_protocol_version_gets_newest_supported_with_diagnostic() {
    let (version, diag) = initialize(&json!({"capabilities": {}}));
    assert_eq!(version, SHIPPED);
    assert!(
        diag.contains("protocolVersion") && diag.contains("downgrade"),
        "missing field: expected stderr downgrade diagnostic, got: {diag}"
    );
}

#[test]
fn issue_6157_non_string_protocol_version_gets_newest_supported_with_diagnostic() {
    for requested in [
        json!(20_241_105),
        json!(null),
        json!({"v": SHIPPED}),
        json!([SHIPPED]),
        json!(true),
    ] {
        let (version, diag) = initialize(&json!({"protocolVersion": requested}));
        assert_eq!(version, SHIPPED, "requested {requested}");
        assert!(
            diag.contains("protocolVersion") && diag.contains("downgrade"),
            "requested {requested}: expected stderr downgrade diagnostic, got: {diag}"
        );
    }
}

/// Send one `initialize` per entry of `versions` (the requested
/// `protocolVersion`, in order) down ONE child and return the number of
/// replies plus everything the child wrote to stderr.
fn initialize_repeated(versions: &[&str]) -> (u64, String) {
    let fixture = mcp_stdio_child::Fixture::new();
    let mut child = fixture
        .command()
        .args(["mcp", "--profile", "full", "--tier", "keyword"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("MCP child");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    for (id, version) in (1_u64..).zip(versions) {
        let request = json!({
            "jsonrpc":"2.0","id":id,"method":"initialize",
            "params":{"protocolVersion": version}
        });
        writeln!(stdin, "{request}").expect("write initialize");
    }
    stdin.flush().expect("flush");
    let count = u64::try_from(versions.len()).expect("request count fits u64");
    let mut replies = 0;
    while replies < count {
        let line = rx.recv_timeout(WAIT).expect("initialize response");
        let response: Value = serde_json::from_str(&line).expect("JSON-RPC response");
        assert_eq!(response["result"]["protocolVersion"], SHIPPED);
        replies += 1;
    }
    drop(stdin);
    let mut diag = String::new();
    let _ = stderr.read_to_string(&mut diag);
    let _ = child.wait();
    (replies, diag)
}

/// The downgrade diagnostic is advisory and must not scale with request
/// volume: a host that never drains stderr would otherwise fill the pipe
/// buffer and stall the single-threaded stdio loop (S3 of the #6157 security
/// review). One line per process is enough for an operator to see why.
#[test]
fn issue_6157_downgrade_diagnostic_is_emitted_once_per_process() {
    let (replies, diag) = initialize_repeated(&[UNSUPPORTED; 5]);
    assert_eq!(replies, 5);
    let lines = diag.lines().filter(|l| l.contains("downgrade")).count();
    assert_eq!(
        lines, 1,
        "five downgraded initialize requests must produce exactly one diagnostic line, got: {diag}"
    );
}

/// #6523: a supported `initialize` must not consume the once-per-process
/// downgrade diagnostic. The guard evaluates `downgraded` BEFORE swapping the
/// flag; with the operands reversed the first (supported) request would set
/// the flag and every later downgrade in the process would be silent.
#[test]
fn issue_6523_supported_initialize_does_not_consume_the_downgrade_diagnostic() {
    let (replies, diag) = initialize_repeated(&[SHIPPED, UNSUPPORTED, UNSUPPORTED]);
    assert_eq!(replies, 3);
    let lines = diag.lines().filter(|l| l.contains("downgrade")).count();
    assert_eq!(
        lines, 1,
        "a supported then two downgraded initialize requests must produce exactly one diagnostic line, got: {diag}"
    );
}

/// #7020 (R23): a supported `initialize` between two downgraded ones must not
/// re-arm the once-per-process flag. A mutant that stores `false` into the
/// flag on a supported request would print the diagnostic again for the
/// third request (sequence unsupported, supported, unsupported).
#[test]
fn issue_7020_supported_initialize_does_not_rearm_the_downgrade_diagnostic() {
    let (replies, diag) = initialize_repeated(&[UNSUPPORTED, SHIPPED, UNSUPPORTED]);
    assert_eq!(replies, 3);
    let lines = diag.lines().filter(|l| l.contains("downgrade")).count();
    assert_eq!(
        lines, 1,
        "unsupported, supported, unsupported must produce exactly one diagnostic line, got: {diag}"
    );
}

/// The diagnostic line for a request whose `params` is `params`.
fn diagnostic_for(params: &Value) -> String {
    protocol_downgrade_diagnostic(params, NEWEST_PROTOCOL_REVISION)
}

/// #7003 (S05): a request with no `protocolVersion` is reported as
/// `<missing>`; nothing else from the request params reaches the line
/// (mutant S05 echoed the whole params object).
#[test]
fn issue_7003_a_missing_protocol_version_is_reported_as_missing_and_echoes_nothing() {
    let params = json!({
        "clientInfo": {"name": "MARK6157\u{2028}client"},
        "capabilities": {"x": "MARK6157"}
    });
    let line = diagnostic_for(&params);
    assert!(line.contains("<missing>"), "{line}");
    assert!(!line.contains("MARK6157"), "request params leaked: {line}");
    assert!(!line.contains('\u{2028}'), "raw U+2028 in the line: {line}");
    assert!(line.len() < 400, "line is {} bytes: {line}", line.len());
    let non_string = diagnostic_for(&json!({"protocolVersion": {"k": "MARK6157"}}));
    assert!(non_string.contains("<non-string>"), "{non_string}");
    assert!(!non_string.contains("MARK6157"), "{non_string}");
}

/// #7004 (S12): the clip is 64 CHARACTERS, not bytes: with multi-byte
/// characters exactly the first 64 are echoed (mutant S12 clipped on a byte
/// count and cut or kept the wrong amount), the tail is absent and the line
/// stays short.
#[test]
fn issue_7004_the_echo_clip_counts_characters_not_bytes() {
    let value = format!(
        "{}\u{1F600}TAIL{}",
        "\u{e9}".repeat(63),
        "\u{e9}".repeat(4000)
    );
    let line = diagnostic_for(&json!({"protocolVersion": value}));
    let want = format!("\"{}\u{1F600}\"", "\u{e9}".repeat(63));
    assert!(
        line.contains(&want),
        "first 64 chars not echoed exactly: {line}"
    );
    assert!(!line.contains("TAIL"), "text past the clip leaked: {line}");
    assert!(line.len() < 400, "line is {} bytes", line.len());

    let value = format!("a{}", "\u{e9}".repeat(100));
    let line = diagnostic_for(&json!({"protocolVersion": value}));
    let want = format!("\"a{}\"", "\u{e9}".repeat(63));
    assert!(
        line.contains(&want),
        "first 64 chars not echoed exactly: {line}"
    );
    assert!(
        !line.contains(&"\u{e9}".repeat(64)),
        "more than 64 chars echoed: {line}"
    );
}

/// #7003 end to end: the missing-field diagnostic a real child writes names
/// `<missing>` and carries nothing from the request.
#[test]
fn issue_7003_a_real_child_reports_a_missing_revision_without_echoing_params() {
    let (version, diag) = initialize(&json!({"clientInfo": {"name": "MARK6157"}}));
    assert_eq!(version, SHIPPED);
    assert!(diag.contains("<missing>"), "{diag}");
    assert!(!diag.contains("MARK6157"), "{diag}");
}

/// #7006 (S08): a stderr nobody can write to must not stop the stdio loop.
/// The child answers a supported `initialize`, the test drops the read end of
/// its stderr pipe, and the downgraded `initialize` plus a `ping` that
/// follow must both still be answered. Mutant S08 (`eprintln!`) panics on the
/// broken pipe and the second reply never arrives (ERRORS-19).
#[test]
fn issue_7006_a_broken_stderr_does_not_stop_the_stdio_loop() {
    let fixture = mcp_stdio_child::Fixture::new();
    let mut child = fixture
        .command()
        .args(["mcp", "--profile", "full", "--tier", "keyword"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("MCP child");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let first = json!({
        "jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion": SHIPPED}
    });
    writeln!(stdin, "{first}").expect("write first initialize");
    stdin.flush().expect("flush");
    rx.recv_timeout(WAIT).expect("first initialize response");
    // The child is up and serving; now nobody can read its stderr.
    drop(stderr);
    let second = json!({
        "jsonrpc":"2.0","id":2,"method":"initialize",
        "params":{"protocolVersion": UNSUPPORTED}
    });
    let ping = json!({"jsonrpc":"2.0","id":3,"method":"ping"});
    writeln!(stdin, "{second}").expect("write downgraded initialize");
    writeln!(stdin, "{ping}").expect("write ping");
    stdin.flush().expect("flush");
    for want_id in [2_u64, 3] {
        let line = rx
            .recv_timeout(WAIT)
            .unwrap_or_else(|_| panic!("no reply for id {want_id}: the loop stopped"));
        let response: Value = serde_json::from_str(&line).expect("JSON-RPC response");
        assert_eq!(response["id"], want_id, "{response}");
        assert!(response.get("error").is_none(), "{response}");
    }
    drop(stdin);
    let _ = child.wait();
}
