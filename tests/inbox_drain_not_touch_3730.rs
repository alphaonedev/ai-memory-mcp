// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3730 — the agent inbox is the PENDING set: handled = deleted by the
//! recipient, reads never mark anything, and a message that leaves the inbox
//! is ARCHIVED (the inbox's delete retention policy), not erased.
//!
//! Pre-#3730 "unread" was inferred from `access_count == 0`, a TOUCH counter no
//! inbox operation advanced, so nothing could mark a message read and a
//! sender loop keyed on the marker re-delivered forever (the fleet's own wake
//! plane: 50/50 unread against 237 handled ids in a side ledger).
//!
//! Every cell drives the REAL binary — the MCP stdio server as the recipient
//! (`AI_MEMORY_AGENT_ID`), and the CLI — so the funnels a customer uses are
//! the funnels pinned. Fail-before / pass-after on `f0175b709`:
//!
//! * `recipient_delete_archives_and_drains_every_read_surface_3730` —
//!   `memory_delete` answers `archived: true` (absent pre-fix), and the row
//!   is gone from `memory_inbox`, `memory_get` and `memory_recall` while
//!   `memory_archive_list` holds it (pre-fix: erased, archive empty).
//! * `non_inbox_row_deleted_the_same_way_is_still_erased_3730` — the
//!   negative control that keeps the inbox policy from silently becoming
//!   product-wide: `archived: false`, archive empty.
//! * `sender_loop_keyed_on_the_inbox_observes_a_message_exactly_once_3730` —
//!   the #3730 symptom, end to end.
//! * `cli_hard_delete_on_an_inbox_row_warns_then_erases_3730` — `--hard`
//!   still erases (an operator's legitimate erasure) but names what it
//!   destroys first; plain `delete` archives and says `archived: true`.
//! * `touched_message_still_lists_under_unread_only_3730` — a message whose
//!   `access_count` was bumped (the old "read" marker) still lists: a touch
//!   is not a handling. Pre-fix `--unread-only` hid it.

#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const ALICE: &str = "ai:alice-3730";
const BOB: &str = "ai:bob-3730";

fn scratch() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir_in(".local-runs").expect("scratch dir under the repo");
    let db = dir.path().join("inbox-3730.db");
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).expect("home");
    (dir, db, home)
}

/// One `tools/call` against the real MCP stdio server, as `caller`.
fn mcp(
    db: &std::path::Path,
    home: &std::path::Path,
    caller: &str,
    tool: &str,
    args: &Value,
) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", caller)
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("HOME", home)
        .args([
            "--db",
            db.to_str().expect("db path"),
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
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":tool,"arguments":args}});
    writeln!(child.stdin.take().expect("stdin"), "{request}").expect("request");
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait().expect("poll").is_none() {
        assert!(Instant::now() < deadline, "MCP child timed out on {tool}");
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("output");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let response = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|v| v["id"] == 1)
        .unwrap_or_else(|| {
            panic!(
                "no response for {caller} {tool}: status={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
        });
    if let Some(text) = response["result"]["content"][0]["text"].as_str() {
        if response["result"]["isError"].as_bool() == Some(true) {
            return json!({"error": text});
        }
        return serde_json::from_str(text).unwrap_or_else(|_| json!({"text": text}));
    }
    json!({"error": response["error"].clone()})
}

/// `ai-memory <args>` as `caller`, returning (status ok, stdout, stderr).
fn cli(
    db: &std::path::Path,
    home: &std::path::Path,
    caller: &str,
    args: &[&str],
) -> (bool, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("HOME", home)
        .args(["--db", db.to_str().expect("db path"), "--agent-id", caller])
        .args(args)
        .output()
        .expect("cli");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn notify(db: &std::path::Path, home: &std::path::Path, title: &str) -> String {
    let receipt = mcp(
        db,
        home,
        ALICE,
        "memory_notify",
        &json!({"target_agent_id": BOB, "title": title, "payload": format!("payload for {title}")}),
    );
    receipt["id"]
        .as_str()
        .unwrap_or_else(|| panic!("notify receipt carries the id: {receipt}"))
        .to_string()
}

fn inbox_ids(db: &std::path::Path, home: &std::path::Path, unread_only: bool) -> Vec<String> {
    let out = mcp(
        db,
        home,
        BOB,
        "memory_inbox",
        &json!({"unread_only": unread_only, "limit": 50}),
    );
    let messages = out["messages"]
        .as_array()
        .unwrap_or_else(|| panic!("inbox envelope: {out}"));
    assert_eq!(out["count"], json!(messages.len()));
    assert_eq!(
        out["unread_count"],
        json!(messages.len()),
        "unread_count == count by contract"
    );
    for m in messages {
        assert!(
            m.get("read").is_none(),
            "#3730: no `read` field on the wire: {m}"
        );
    }
    messages
        .iter()
        .filter_map(|m| m["id"].as_str().map(str::to_string))
        .collect()
}

fn archived_ids(db: &std::path::Path, home: &std::path::Path, namespace: &str) -> Vec<String> {
    let out = mcp(
        db,
        home,
        BOB,
        "memory_archive_list",
        &json!({"namespace": namespace, "limit": 50}),
    );
    out["archived"]
        .as_array()
        .unwrap_or_else(|| panic!("archive list: {out}"))
        .iter()
        .filter_map(|m| m["id"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn recipient_delete_archives_and_drains_every_read_surface_3730() {
    let (_dir, db, home) = scratch();
    let id = notify(&db, &home, "kumquat directive");
    assert_eq!(inbox_ids(&db, &home, true), vec![id.clone()], "delivered");

    // The recipient declares it handled: delete. The disposition is ON THE WIRE.
    let deleted = mcp(&db, &home, BOB, "memory_delete", &json!({"id": id}));
    assert_eq!(deleted["deleted"], json!(true), "{deleted}");
    assert_eq!(
        deleted["archived"],
        json!(true),
        "#3730: an inbox message is ARCHIVED on delete, and the response says so: {deleted}"
    );

    // Gone from every read surface ...
    assert!(inbox_ids(&db, &home, false).is_empty(), "inbox drained");
    let got = mcp(&db, &home, BOB, "memory_get", &json!({"id": id}));
    assert!(
        got.get("error").is_some() || got["id"].is_null(),
        "get must not find an archived row: {got}"
    );
    let recalled = mcp(
        &db,
        &home,
        BOB,
        "memory_recall",
        &json!({"query": "kumquat directive", "namespace": ai_memory::inbox_namespace(BOB), "limit": 10}),
    );
    let recalled_text = recalled.to_string();
    assert!(
        !recalled_text.contains(&id),
        "recall must not surface an archived row: {recalled}"
    );

    // ... and present in the archive: the record of what bob was told survives.
    assert_eq!(
        archived_ids(&db, &home, &ai_memory::inbox_namespace(BOB)),
        vec![id],
        "archive holds the drained message"
    );
}

#[test]
fn non_inbox_row_deleted_the_same_way_is_still_erased_3730() {
    let (_dir, db, home) = scratch();
    let stored = mcp(
        &db,
        &home,
        BOB,
        "memory_store",
        &json!({"title": "ordinary note", "content": "not an inbox message", "namespace": "notes-3730"}),
    );
    let id = stored["id"]
        .as_str()
        .unwrap_or_else(|| panic!("store receipt: {stored}"))
        .to_string();
    let deleted = mcp(&db, &home, BOB, "memory_delete", &json!({"id": id}));
    assert_eq!(deleted["deleted"], json!(true), "{deleted}");
    assert_eq!(
        deleted["archived"],
        json!(false),
        "negative control: the inbox retention policy must not leak to other namespaces: {deleted}"
    );
    assert!(
        archived_ids(&db, &home, "notes-3730").is_empty(),
        "an ordinary delete leaves no archive copy"
    );
}

#[test]
fn sender_loop_keyed_on_the_inbox_observes_a_message_exactly_once_3730() {
    let (_dir, db, home) = scratch();
    let id = notify(&db, &home, "please build #3730");
    let mut observed = 0usize;
    // The wake-plane consumer shape: read what is pending, handle it, drain it.
    for _ in 0..3 {
        let pending = inbox_ids(&db, &home, true);
        for msg in &pending {
            observed += 1;
            let deleted = mcp(&db, &home, BOB, "memory_delete", &json!({"id": msg}));
            assert_eq!(deleted["archived"], json!(true), "{deleted}");
        }
    }
    assert_eq!(
        observed, 1,
        "#3730: a handled message is never re-delivered"
    );
    assert_eq!(
        archived_ids(&db, &home, &ai_memory::inbox_namespace(BOB)),
        vec![id]
    );
}

#[test]
fn touched_message_still_lists_under_unread_only_3730() {
    let (_dir, db, home) = scratch();
    let id = notify(&db, &home, "touched but not handled");
    {
        // The fold's write, verbatim: a TOUCH. Pre-#3730 this was the "read" marker.
        let conn = rusqlite::Connection::open(&db).expect("open");
        let n = conn
            .execute(
                "UPDATE memories SET access_count = 1 WHERE id = ?1",
                rusqlite::params![id],
            )
            .expect("touch");
        assert_eq!(n, 1);
    }
    assert_eq!(
        inbox_ids(&db, &home, true),
        vec![id],
        "#3730: `unread_only` narrows nothing — a touched message is still pending"
    );
}

#[test]
fn cli_hard_delete_on_an_inbox_row_warns_then_erases_3730() {
    let (_dir, db, home) = scratch();
    let ns = ai_memory::inbox_namespace(BOB);
    let first = notify(&db, &home, "erase me");
    let second = notify(&db, &home, "archive me");

    // --hard: legitimate, never silent. One line naming what is destroyed.
    let (ok, stdout, stderr) = cli(&db, &home, BOB, &["--json", "delete", &first, "--hard"]);
    assert!(ok, "hard delete must proceed: {stderr}");
    assert!(
        stderr.contains("warning: --hard on inbox message") && stderr.contains(&first),
        "#3730: --hard on an inbox row names what it destroys; stderr={stderr}"
    );
    let v: Value = serde_json::from_str(stdout.trim()).expect("json");
    assert_eq!(v["archived"], json!(false));
    assert!(
        !archived_ids(&db, &home, &ns).contains(&first),
        "erased, not archived"
    );

    // plain delete: the drain idiom, archived, and it says so.
    let (ok, stdout, stderr) = cli(&db, &home, BOB, &["--json", "delete", &second]);
    assert!(ok, "{stderr}");
    assert!(
        !stderr.contains("warning: --hard"),
        "no warning on the archive path: {stderr}"
    );
    let v: Value = serde_json::from_str(stdout.trim()).expect("json");
    assert_eq!(v["archived"], json!(true));
    assert_eq!(archived_ids(&db, &home, &ns), vec![second]);
    assert!(inbox_ids(&db, &home, false).is_empty());
}
