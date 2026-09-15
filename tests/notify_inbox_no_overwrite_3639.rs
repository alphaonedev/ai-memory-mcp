// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3639 — a `notify` with a repeated title to the same recipient must be a
//! NEW inbox row: never overwrite the earlier body, never keep the earlier
//! sender's attribution, never hand two senders the same row id. Exercised
//! through the compiled binary (the exact repro from the issue) and through
//! the sqlite SAL adapter's wake emission. Every test FAILS on f0175b709:
//! there the second delivery merged into the first row (count 1, body from
//! mallory, `from` alice, same id).

use std::path::Path;
use std::process::Command;
#[cfg(feature = "sal")]
use std::time::Duration;

// The wake-plane probe runs under the SAL build only (the store trait
// lives behind `sal`); its helpers are gated the same way.
#[cfg(feature = "sal")]
use ai_memory::inbox_wake::{InboxEvent, subscribe};
use serde_json::Value;

fn ai_memory(root: &Path, agent: &str) -> Command {
    let keys = root.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("AI_MEMORY_KEY_DIR", &keys)
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", agent)
        .args([
            "--db",
            root.join("t.db").to_str().unwrap(),
            "--agent-id",
            agent,
        ]);
    cmd
}

fn json_stdout(out: &std::process::Output) -> Value {
    let text = String::from_utf8_lossy(&out.stdout);
    let start = text.find('{').expect("JSON envelope on stdout");
    serde_json::from_str(&text[start..]).expect("parse inbox JSON")
}

fn notify(root: &Path, sender: &str, title: &str, payload: &str) -> Value {
    let out = ai_memory(root, sender)
        .args([
            "notify",
            "--target-agent-id",
            "ai:bob",
            "--title",
            title,
            "--payload",
            payload,
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "notify must deliver: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    json_stdout(&out)
}

/// The issue's repro, verbatim: alice then mallory notify bob under the same
/// title; bob's inbox must hold BOTH rows with their own senders and bodies.
#[test]
fn repeated_title_yields_two_rows_with_their_own_senders_3639() {
    let root = tempfile::tempdir().unwrap();
    let a = notify(
        root.path(),
        "ai:alice",
        "deploy approval",
        "ALICE: approve deploy 42",
    );
    let b = notify(
        root.path(),
        "ai:mallory",
        "deploy approval",
        "MALLORY-FORGED: approve deploy 666",
    );
    assert_ne!(
        a["id"], b["id"],
        "#3639: both senders must get distinct row ids"
    );
    assert_eq!(a["subject"], "deploy approval");

    let out = ai_memory(root.path(), "ai:bob")
        .args(["inbox", "--json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let inbox = json_stdout(&out);
    assert_eq!(inbox["count"].as_u64(), Some(2), "#3639: {inbox}");
    let msgs = inbox["messages"].as_array().unwrap();
    let find = |id: &Value| msgs.iter().find(|m| m["id"] == *id).expect("row listed");
    let ra = find(&a["id"]);
    let rb = find(&b["id"]);
    assert_eq!(ra["from"], "ai:alice");
    assert_eq!(ra["agent_id"], "ai:alice");
    assert_eq!(ra["content"], "ALICE: approve deploy 42");
    assert_eq!(rb["from"], "ai:mallory");
    assert_eq!(rb["agent_id"], "ai:mallory");
    assert_eq!(rb["content"], "MALLORY-FORGED: approve deploy 666");
    for r in [ra, rb] {
        assert_eq!(r["read"], false, "a fresh delivery is unread: {r}");
        assert_eq!(r["subject"], "deploy approval");
    }
}

/// A sender re-using its own subject never loses its earlier message.
#[test]
fn same_sender_repeated_subject_keeps_both_messages_3639() {
    let root = tempfile::tempdir().unwrap();
    let a = notify(root.path(), "ai:alice", "STATUS", "first");
    let b = notify(root.path(), "ai:alice", "STATUS", "second");
    assert_ne!(a["id"], b["id"]);
    let out = ai_memory(root.path(), "ai:bob")
        .args(["inbox", "--json", "--unread-only"])
        .output()
        .unwrap();
    let inbox = json_stdout(&out);
    assert_eq!(inbox["count"].as_u64(), Some(2), "{inbox}");
    let bodies: Vec<&str> = inbox["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["content"].as_str().unwrap())
        .collect();
    assert!(
        bodies.contains(&"first") && bodies.contains(&"second"),
        "{bodies:?}"
    );
}

#[cfg(feature = "sal")]
async fn wake_for(
    rx: &mut tokio::sync::broadcast::Receiver<InboxEvent>,
    recipient: &str,
) -> Option<InboxEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(ev)) if ev.recipient_agent_id() == recipient => return Some(ev),
            Ok(Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) | Err(_) => return None,
        }
    }
}

/// The wake plane names a NEW row for the second delivery (on the head it
/// re-woke the recipient for the SAME row id, so nothing downstream could
/// tell a replacement had happened).
#[cfg(feature = "sal")]
#[tokio::test]
async fn second_delivery_wakes_for_a_new_row_3639() {
    use ai_memory::store::MemoryStore as _;
    let root = tempfile::tempdir().unwrap();
    let recipient = format!("ai:wake-{}", uuid::Uuid::new_v4().simple());
    let store = ai_memory::store::sqlite::SqliteStore::open(root.path().join("sal.db"))
        .expect("SqliteStore");
    let alice = ai_memory::store::CallerContext::for_agent("ai:alice");
    let mallory = ai_memory::store::CallerContext::for_agent("ai:mallory");
    let mut rx = subscribe();
    let first = store
        .notify(
            &alice,
            &recipient,
            "deploy approval",
            "A",
            Some(5),
            None,
            None,
        )
        .await
        .expect("first delivery");
    let ev1 = wake_for(&mut rx, &recipient).await.expect("first wake");
    let second = store
        .notify(
            &mallory,
            &recipient,
            "deploy approval",
            "B",
            Some(5),
            None,
            None,
        )
        .await
        .expect("second delivery");
    let ev2 = wake_for(&mut rx, &recipient).await.expect("second wake");
    assert_ne!(first, second, "#3639: a second delivery is a new row");
    let InboxEvent::AgentNotified {
        inbox_row_id: id1, ..
    } = ev1;
    let InboxEvent::AgentNotified {
        inbox_row_id: id2, ..
    } = ev2;
    assert_eq!(id1, first);
    assert_eq!(id2, second);
    assert_ne!(
        id1, id2,
        "#3639: the wake names the NEW row, never the old one"
    );
}
