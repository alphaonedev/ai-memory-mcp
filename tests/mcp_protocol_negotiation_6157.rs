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

use serde_json::{Value, json};

#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;
#[path = "common/mcp_wait.rs"]
mod mcp_wait;

/// The one revision the server implements end to end today (the SSOT pin in
/// `mcp_protocol_revision_ssot_6157.rs` proves this is a member of
/// `SUPPORTED_PROTOCOL_REVISIONS`).
const SHIPPED: &str = "2024-11-05";
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

/// Send `count` downgrade `initialize` requests down ONE child and return
/// the number of replies plus everything the child wrote to stderr.
fn initialize_repeated(count: u64) -> (u64, String) {
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
    for id in 1..=count {
        let request = json!({
            "jsonrpc":"2.0","id":id,"method":"initialize",
            "params":{"protocolVersion":"2099-01-01"}
        });
        writeln!(stdin, "{request}").expect("write initialize");
    }
    stdin.flush().expect("flush");
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
    let (replies, diag) = initialize_repeated(5);
    assert_eq!(replies, 5);
    let lines = diag.lines().filter(|l| l.contains("downgrade")).count();
    assert_eq!(
        lines, 1,
        "five downgraded initialize requests must produce exactly one diagnostic line, got: {diag}"
    );
}
