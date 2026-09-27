// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4064 — oversize-line recovery on the MCP stdio loop must not discard the
//! requests buffered behind the offending line.
//!
//! The pre-#4064 drain read whole 8 KiB chunks and stopped at the first chunk
//! containing a newline, throwing away every byte after that newline in the
//! same chunk — so JSON-RPC frames a client had already written behind a
//! malformed one got no response. Driven through a real `ai-memory mcp`
//! child whose stdin is a regular FILE (explicitly accepted by
//! `src/mcp/stdio_guard.rs`; a coalesced pipe buffers the same way): one
//! `MCP_MAX_LINE_BYTES + k` line, then pipelined pings.
//!
//! Cells:
//!   * RED on the untouched tip — exactly one oversize `-32700`, then a reply
//!     for EVERY pipelined ping, for several terminator offsets inside the
//!     buffered chunk (the pings share the chunk with the newline).
//!   * a final frame with no trailing newline at EOF is still served.
//!   * a truncated trailing frame yields one ordinary parse error, not a
//!     silent drop.

use std::io::Write as _;
use std::process::Stdio;

use ai_memory::mcp::MCP_MAX_LINE_BYTES;
use serde_json::Value;

#[path = "common/mcp_wait.rs"]
mod mcp_wait;

#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;

use mcp_stdio_child::Fixture;

fn ping(id: u64) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"ping"}}"#)
}

/// Run the child over `stdin_bytes` (as a regular file) and return every
/// JSON-RPC response line it wrote before exiting on EOF.
fn run_over_file(fixture: &Fixture, stdin_bytes: &[u8]) -> Vec<Value> {
    let path = fixture.dir.path().join("stdin.jsonl");
    let mut file = std::fs::File::create(&path).expect("stdin file");
    file.write_all(stdin_bytes).expect("write stdin");
    file.sync_all().expect("sync stdin");
    drop(file);
    let output = fixture
        .command()
        .args(["mcp", "--profile", "core", "--tier", "keyword"])
        .stdin(std::fs::File::open(&path).expect("reopen stdin"))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("MCP child");
    String::from_utf8(output.stdout)
        .expect("utf-8 stdout")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("JSON-RPC line"))
        .collect()
}

fn oversize_line(extra: usize) -> Vec<u8> {
    let mut bytes = vec![b'x'; MCP_MAX_LINE_BYTES + extra];
    bytes.push(b'\n');
    bytes
}

fn is_oversize_error(v: &Value) -> bool {
    v["error"]["code"] == -32700
        && v["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("line exceeded"))
}

fn reply_ids(responses: &[Value]) -> Vec<u64> {
    responses
        .iter()
        .filter(|v| v.get("error").is_none())
        .filter_map(|v| v["id"].as_u64())
        .collect()
}

#[test]
fn pipelined_requests_after_an_oversize_line_are_all_served_4064() {
    let fixture = Fixture::new();
    // Vary where the offending newline lands inside the 8 KiB stdin chunk.
    for extra in [1usize, 777, 8191] {
        let mut input = oversize_line(extra);
        for id in 2..=4 {
            input.extend_from_slice(ping(id).as_bytes());
            input.push(b'\n');
        }
        let responses = run_over_file(&fixture, &input);
        let oversize = responses.iter().filter(|v| is_oversize_error(v)).count();
        assert_eq!(
            oversize, 1,
            "extra={extra}: exactly one oversize parse error: {responses:?}"
        );
        assert_eq!(
            reply_ids(&responses),
            vec![2, 3, 4],
            "extra={extra}: every pipelined request behind the oversize line is served"
        );
        assert_eq!(
            responses.len(),
            4,
            "extra={extra}: no spurious extra errors from a truncated tail: {responses:?}"
        );
    }
}

#[test]
fn final_frame_without_newline_and_truncated_tail_after_oversize_4064() {
    let fixture = Fixture::new();

    // A complete last frame with no trailing newline is still served.
    let mut input = oversize_line(3);
    input.extend_from_slice(ping(2).as_bytes());
    input.push(b'\n');
    input.extend_from_slice(ping(3).as_bytes());
    let responses = run_over_file(&fixture, &input);
    assert_eq!(reply_ids(&responses), vec![2, 3], "{responses:?}");

    // A truncated trailing frame is ONE ordinary parse error, never a drop of
    // the complete frame in front of it.
    let mut input = oversize_line(5);
    input.extend_from_slice(ping(2).as_bytes());
    input.push(b'\n');
    input.extend_from_slice(br#"{"jsonrpc":"2.0","id":3,"meth"#);
    let responses = run_over_file(&fixture, &input);
    assert_eq!(reply_ids(&responses), vec![2], "{responses:?}");
    let parse_errors = responses
        .iter()
        .filter(|v| v["error"]["code"] == -32700)
        .count();
    assert_eq!(
        parse_errors, 2,
        "one oversize error + one truncated-frame error: {responses:?}"
    );
}
