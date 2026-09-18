// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3730 (follow-up; the #2572 class) — `ai-memory inbox` and `ai-memory
//! notify` on a Postgres-served deployment, through the REAL binary.
//!
//! The inbox is the PENDING set in the SERVED store (#3730). Both CLI verbs
//! opened the local SQLite `--db` directly with no store resolution, so with
//! `AI_MEMORY_STORE_URL=postgres://…` a `notify` phantom-landed the message
//! in a sidecar the daemon never reads (reported as delivered; the recipient
//! never sees it) and an `inbox` read reported an EMPTY inbox while messages
//! waited in Postgres — the two halves of the #2572 defect, missed by its
//! census because the census counts guard calls, not `db::open` sites.
//!
//! FAILS ON THE BASE (0fcd36f82): both verbs exit 0 under the pg URL —
//! `notify` writes the sidecar, `inbox` lists it as empty.
//!
//! Sinks: the exit status and stderr (the typed #2572 refusal naming the
//! HTTP-daemon remedy, never the DSN password), and the sidecar (nothing
//! phantom-landed). Control on the same sinks: without a store URL `notify`
//! then `inbox` lists exactly that message. The DSN's host:port is never
//! connected — the refusal happens before any store is opened.

use std::path::Path;
use std::process::{Command, Output};

const SENDER: &str = "ai:sender-3730";
const RECIPIENT: &str = "ai:recipient-3730";
/// Never connected: port 1 on loopback; the guard refuses on the scheme.
const PG_STORE_URL: &str = "postgres://ai_memory:hunter2@127.0.0.1:1/ai_memory_3730";

fn command(root: &Path, agent: &str, store_url: Option<&str>) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ai-memory"));
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/.config"))
        .env("AI_MEMORY_KEY_DIR", root.join("keys"))
        .env("AI_MEMORY_DB", root.join("store.db"))
        .env("AI_MEMORY_AUDIT_DIR", root.join("audit"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_AGENT_ID", agent)
        .env("AI_MEMORY_REQUIRE_AGENT_ATTESTATION", "0")
        .env("RUST_LOG", "error");
    if let Some(url) = store_url {
        cmd.env("AI_MEMORY_STORE_URL", url);
    }
    cmd
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().expect("spawn ai-memory")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn inbox_count(root: &Path, store_url: Option<&str>) -> (Output, Option<u64>) {
    let out = run(command(root, RECIPIENT, store_url).args(["--json", "inbox"]));
    let count =
        serde_json::from_str::<serde_json::Value>(String::from_utf8_lossy(&out.stdout).trim())
            .ok()
            .and_then(|v| v["count"].as_u64());
    (out, count)
}

fn assert_typed_pg_refusal(out: &Output, verb: &str) {
    let t = text(out);
    assert!(
        !out.status.success(),
        "#3730: `{verb}` must REFUSE on a Postgres store, got exit 0:\n{t}"
    );
    assert!(t.contains("#2572"), "{verb}: the refusal cites #2572:\n{t}");
    assert!(
        t.contains("HTTP daemon"),
        "{verb}: the refusal names the HTTP-daemon remedy:\n{t}"
    );
    assert!(
        !t.contains("hunter2"),
        "{verb}: the refusal never carries the DSN password:\n{t}"
    );
}

/// `notify` on a Postgres store refuses before any write: nothing lands in
/// the sidecar (read back without the store URL: 0 messages).
#[test]
fn notify_refuses_on_a_postgres_store_and_phantom_writes_nothing_3730() {
    let root = tempfile::tempdir().unwrap();
    let out = run(command(root.path(), SENDER, Some(PG_STORE_URL)).args([
        "notify",
        "--target-agent-id",
        RECIPIENT,
        "--title",
        "hello",
        "--payload",
        "phantom?",
    ]));
    assert_typed_pg_refusal(&out, "notify");
    let (read, count) = inbox_count(root.path(), None);
    assert!(read.status.success(), "{}", text(&read));
    assert_eq!(
        count,
        Some(0),
        "nothing phantom-landed in the sidecar: {}",
        text(&read)
    );
}

/// `inbox` on a Postgres store refuses instead of reporting the sidecar's
/// empty inbox as the answer; `inbox --wait` refuses the same way after its
/// bounded wait.
#[test]
fn inbox_refuses_on_a_postgres_store_instead_of_an_empty_answer_3730() {
    let root = tempfile::tempdir().unwrap();
    let (out, count) = inbox_count(root.path(), Some(PG_STORE_URL));
    assert_typed_pg_refusal(&out, "inbox");
    assert_eq!(
        count,
        None,
        "no envelope is emitted on a refusal: {}",
        text(&out)
    );
    let out = run(command(root.path(), RECIPIENT, Some(PG_STORE_URL)).args([
        "inbox",
        "--wait",
        "--timeout",
        "1",
    ]));
    assert_typed_pg_refusal(&out, "inbox --wait");
}

/// Control on the same sinks: without a store URL the local SQLite IS the
/// store — `notify` lands the message and `inbox` lists exactly it.
#[test]
fn without_a_store_url_notify_then_inbox_round_trips_3730() {
    let root = tempfile::tempdir().unwrap();
    let out = run(command(root.path(), SENDER, None).args([
        "notify",
        "--target-agent-id",
        RECIPIENT,
        "--title",
        "hello",
        "--payload",
        "for real",
    ]));
    assert!(out.status.success(), "{}", text(&out));
    let (read, count) = inbox_count(root.path(), None);
    assert!(read.status.success(), "{}", text(&read));
    assert_eq!(count, Some(1), "{}", text(&read));
    assert!(text(&read).contains("hello"), "{}", text(&read));
}
