// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Exercise actual stdio dispatch, with identity confined to each child.

use ai_memory::{
    db,
    models::{Memory, Tier},
};
use serde_json::{Value, json};
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn call(
    path: &std::path::Path,
    home: &std::path::Path,
    caller: &str,
    tool: &str,
    args: &Value,
) -> Result<Value, String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", caller)
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("HOME", home)
        .args([
            "--db",
            path.to_str().expect("path"),
            "mcp",
            "--profile",
            "full",
            "--tier",
            "keyword",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("mcp child");
    let request = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call", "params":{"name":tool,"arguments":args}});
    writeln!(child.stdin.take().expect("stdin"), "{request}").expect("request");
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("poll").is_none() {
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out child");
            child.wait().expect("reap");
            panic!("MCP child timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("output");
    if !output.status.success() {
        return Err(String::from_utf8(output.stderr).expect("stderr"));
    }
    Ok(String::from_utf8(output.stdout)
        .expect("utf8")
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|v| v["id"] == 1)
        .unwrap_or_else(|| {
            panic!(
                "no response for {caller} {tool}: exit={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        }))
}

fn body(response: &Result<Value, String>) -> Value {
    let response = response.as_ref().expect("successful MCP process");
    assert!(response["error"].is_null(), "{response}");
    assert_ne!(response["result"]["isError"], true, "{response}");
    serde_json::from_str(
        response["result"]["content"][0]["text"]
            .as_str()
            .expect("text"),
    )
    .expect("json")
}

#[test]
fn actual_dispatch_scopes_reads_and_restore_and_rejects_invalid_caller() {
    std::fs::create_dir_all(".local-runs").expect("scratch");
    let dir = tempfile::tempdir_in(".local-runs").expect("dir");
    let path = dir.path().join("archive.db");
    let conn = db::open(&path).expect("db");
    let now = chrono::Utc::now().to_rfc3339();
    let memory = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "alice-notes".into(),
        title: "alice archived secret".into(),
        content: "private body".into(),
        tier: Tier::Long,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id":"ai:alice", "scope":"private"}),
        ..Memory::default()
    };
    let id = db::insert(&conn, &memory).expect("seed");
    assert!(db::archive_memory(&conn, &id, None).expect("archive"));
    drop(conn);
    for (tool, count_key) in [
        ("memory_archive_list", "count"),
        ("memory_archive_stats", "archived_total"),
    ] {
        assert_eq!(
            body(&call(&path, dir.path(), "ai:bob", tool, &json!({})))[count_key],
            0
        );
        assert_eq!(
            body(&call(&path, dir.path(), "ai:alice", tool, &json!({})))[count_key],
            1
        );
    }
    let deny = call(
        &path,
        dir.path(),
        "ai:bob",
        "memory_archive_restore",
        &json!({"id":id}),
    );
    let absent = call(
        &path,
        dir.path(),
        "ai:bob",
        "memory_archive_restore",
        &json!({"id":uuid::Uuid::new_v4().to_string()}),
    );
    assert_eq!(deny, absent, "non-owner must have the missing-id envelope");
    let deny = deny.expect("MCP response");
    assert!(deny["error"].is_object() || deny["result"]["isError"] == true);
    for tool in [
        "memory_archive_list",
        "memory_archive_stats",
        "memory_archive_restore",
    ] {
        let response = call(&path, dir.path(), "../../invalid", tool, &json!({"id":id}));
        assert!(
            response
                .expect_err("invalid identity must fail boot")
                .contains("AI_MEMORY_AGENT_ID is invalid")
        );
    }
    assert_eq!(
        body(&call(
            &path,
            dir.path(),
            "ai:alice",
            "memory_archive_restore",
            &json!({"id":id})
        ))["restored"],
        true
    );
}
