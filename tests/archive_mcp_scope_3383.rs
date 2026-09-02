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
    admins: &str,
    tool: &str,
    args: &Value,
) -> Result<Value, String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", caller)
        .env("AI_MEMORY_ADMIN_AGENT_IDS", admins)
        .env("AI_MEMORY_AUDIT_DIR", home.join("audit"))
        .env("AI_MEMORY_LOG_DIR", home.join("logs"))
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

fn seed(conn: &rusqlite::Connection, owner: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let memory = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "gc-owner-3383".into(),
        title: uuid::Uuid::new_v4().to_string(),
        content: "owner-scoped fixture".into(),
        tier: Tier::Short,
        created_at: now.clone(),
        updated_at: now,
        metadata: json!({"agent_id":owner, "scope":"private"}),
        ..Memory::default()
    };
    db::insert(conn, &memory).expect("seed")
}

fn denied(response: Result<Value, String>) {
    let response = response.expect("MCP process");
    assert!(
        response["error"].is_object() || response["result"]["isError"] == true,
        "{response}"
    );
}

#[test]
fn stdio_admin_purge_and_owner_gc_3383() {
    std::fs::create_dir_all(".local-runs").unwrap();
    let dir = tempfile::tempdir_in(".local-runs").unwrap();
    let path = dir.path().join("memories.db");
    let conn = db::open(&path).unwrap();
    for owner in ["ai:alice", "ai:bob"] {
        let id = seed(&conn, owner);
        assert!(db::archive_memory(&conn, &id, None).unwrap());
    }
    let invoke =
        |caller, admins, tool, args: &Value| call(&path, dir.path(), caller, admins, tool, args);
    for (caller, admins) in [("ai:bob", "ai:root"), ("ai:root", ""), ("ai:root", "*")] {
        denied(invoke(
            caller,
            admins,
            "memory_archive_purge",
            &json!({"as_admin":true}),
        ));
        assert_eq!(db::archive_stats(&conn).unwrap()["archived_total"], 2);
    }
    denied(invoke(
        "ai:bob",
        "ai:root",
        "memory_archive_purge",
        &json!({"agent_id":"ai:root", "as_admin":true}),
    ));
    assert_eq!(
        body(&invoke(
            "ai:bob",
            "ai:root",
            "memory_archive_purge",
            &json!({})
        ))["purged"],
        1
    );
    assert_eq!(db::archive_stats(&conn).unwrap()["archived_total"], 1);
    assert_eq!(
        body(&invoke(
            "ai:root",
            "ai:root",
            "memory_archive_purge",
            &json!({"as_admin":true})
        ))["purged"],
        1
    );

    let alice = seed(&conn, "ai:alice");
    let bob = seed(&conn, "ai:bob");
    conn.execute(
        "UPDATE memories SET expires_at = '2000-01-01T00:00:00+00:00'",
        [],
    )
    .unwrap();
    assert_eq!(
        body(&invoke(
            "ai:bob",
            "ai:root",
            "memory_gc",
            &json!({"dry_run":true})
        ))["collected"],
        1
    );
    assert_eq!(
        body(&invoke("ai:bob", "ai:root", "memory_gc", &json!({})))["collected"],
        1
    );
    let present = |id: &str| {
        conn.query_row("SELECT COUNT(*) FROM memories WHERE id=?1", [id], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap()
    };
    assert_eq!(present(&alice), 1, "other owner's row survives");
    assert_eq!(present(&bob), 0);
    assert_eq!(
        db::archive_stats(&conn).unwrap()["archived_total"],
        1,
        "own row is recoverable"
    );
    assert_eq!(
        body(&invoke("ai:root", "ai:root", "memory_gc", &json!({})))["collected"],
        1
    );
    assert_eq!(present(&alice), 0);
    assert_eq!(db::archive_stats(&conn).unwrap()["archived_total"], 2);
    let decisions = audit_decisions(dir.path());
    for (actor, decision) in [("ai:bob", "refuse"), ("ai:root", "allow")] {
        assert!(
            decisions.iter().any(|row| row["actor"] == actor
                && row["decision"] == decision
                && row["kind"] == "archive_purge"),
            "missing {decision} audit for {actor}: {decisions:?}"
        );
    }
    for caller in ["", "../../invalid"] {
        for tool in ["memory_gc", "memory_archive_purge"] {
            assert!(invoke(caller, "ai:root", tool, &json!({"as_admin":true})).is_err());
        }
    }
}

fn audit_decisions(home: &std::path::Path) -> Vec<Value> {
    std::fs::read_dir(home.join("audit"))
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("forensic-"))
        .flat_map(|entry| {
            std::fs::read_to_string(entry.path())
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}
