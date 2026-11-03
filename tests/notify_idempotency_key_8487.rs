// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #8487 — optional sender idempotency key on `memory_notify`.
//!
//! A retried notify that carries the same `(sender, target, key)` must
//! resolve to the ORIGINAL inbox row (same id, `dedup_hit: true`, no second
//! row); a changed body under a used key is a typed conflict carrying the
//! original id; an invalid key is refused before any quota charge or write;
//! an absent key is today's behaviour. Sqlite cells: the SAL store, the MCP
//! handler and the compiled CLI. The postgres twin is
//! `notify_idempotency_key_8487_pg.rs`.
//!
//! Decision shape: 3-agent vote (6def5ab6).

#![cfg(feature = "sal")]

use ai_memory::models::Tier;
use ai_memory::notify_dedup::{content_digest, validate_idempotency_key};
use ai_memory::store::sqlite::SqliteStore;
use ai_memory::store::{CallerContext, MemoryStore, StoreError};
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

const KEY: &str = "retry-key_1.a:b";
const TARGET: &str = "ai:bob-8487";

fn row_count(db: &Path, target: &str) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("open db");
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
        [ai_memory::inbox_namespace(target)],
        |r| r.get(0),
    )
    .expect("count inbox rows")
}

async fn deliver(
    store: &SqliteStore,
    sender: &str,
    target: &str,
    payload: &str,
    key: Option<&str>,
) -> Result<ai_memory::store::NotifyOutcome, StoreError> {
    store
        .notify_outcome(
            &CallerContext::for_agent(sender),
            target,
            "deploy approval",
            payload,
            Some(5),
            None,
            None,
            key,
        )
        .await
}

#[tokio::test]
async fn same_key_twice_returns_original_id_and_one_row_8487() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("s.db");
    let store = SqliteStore::open(&db).unwrap();
    let a = deliver(&store, "ai:alice", TARGET, "body", Some(KEY))
        .await
        .unwrap();
    let b = deliver(&store, "ai:alice", TARGET, "body", Some(KEY))
        .await
        .unwrap();
    assert!(!a.dedup_hit, "fresh insert is not a dedup hit");
    assert!(b.dedup_hit, "retry is a dedup hit");
    assert_eq!(a.id, b.id, "retry resolves to the original id");
    assert_eq!(row_count(&db, TARGET), 1, "exactly one inbox row");
}

#[tokio::test]
async fn different_target_same_key_is_two_rows_8487() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("s.db");
    let store = SqliteStore::open(&db).unwrap();
    let a = deliver(&store, "ai:alice", TARGET, "body", Some(KEY))
        .await
        .unwrap();
    let b = deliver(&store, "ai:alice", "ai:carol-8487", "body", Some(KEY))
        .await
        .unwrap();
    assert_ne!(a.id, b.id);
    assert!(!b.dedup_hit);
    assert_eq!(row_count(&db, TARGET), 1);
    assert_eq!(row_count(&db, "ai:carol-8487"), 1);
}

#[tokio::test]
async fn different_sender_same_key_is_two_rows_8487() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("s.db");
    let store = SqliteStore::open(&db).unwrap();
    let a = deliver(&store, "ai:alice", TARGET, "body", Some(KEY))
        .await
        .unwrap();
    let b = deliver(&store, "ai:mallory", TARGET, "body", Some(KEY))
        .await
        .unwrap();
    assert_ne!(a.id, b.id, "the sender is part of the key");
    assert!(!b.dedup_hit);
    assert_eq!(row_count(&db, TARGET), 2);
}

#[tokio::test]
async fn mismatched_payload_is_a_conflict_carrying_the_original_id_8487() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("s.db");
    let store = SqliteStore::open(&db).unwrap();
    let a = deliver(&store, "ai:alice", TARGET, "body", Some(KEY))
        .await
        .unwrap();
    let err = deliver(&store, "ai:alice", TARGET, "DIFFERENT body", Some(KEY))
        .await
        .expect_err("changed body under a used key conflicts");
    match err {
        StoreError::Conflict { id } => assert_eq!(id, a.id, "conflict carries the original id"),
        other => panic!("expected Conflict, got {other:?}"),
    }
    assert_eq!(row_count(&db, TARGET), 1, "a conflict writes nothing");
}

#[tokio::test]
async fn invalid_keys_are_refused_before_any_write_or_quota_charge_8487() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("s.db");
    let store = SqliteStore::open(&db).unwrap();
    let too_long = "k".repeat(129);
    for bad in [
        "",
        "   ",
        "has space",
        too_long.as_str(),
        "emoji\u{1F600}",
        "semi;colon",
    ] {
        let err = deliver(&store, "ai:alice", TARGET, "body", Some(bad))
            .await
            .expect_err("invalid key refused");
        assert!(
            matches!(err, StoreError::InvalidInput { .. }),
            "typed validation error for {bad:?}: {err:?}"
        );
    }
    assert_eq!(row_count(&db, TARGET), 0, "no row for a refused key");
    let conn = rusqlite::Connection::open(&db).unwrap();
    let used: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM agent_quotas WHERE agent_id = 'ai:alice'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    assert_eq!(used, 0, "no quota row was charged for a refused key");
}

#[tokio::test]
async fn absent_key_is_todays_behaviour_8487() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("s.db");
    let store = SqliteStore::open(&db).unwrap();
    let a = deliver(&store, "ai:alice", TARGET, "body", None)
        .await
        .unwrap();
    let b = deliver(&store, "ai:alice", TARGET, "body", None)
        .await
        .unwrap();
    assert_ne!(a.id, b.id, "no key: every delivery is a new row");
    assert!(!a.dedup_hit && !b.dedup_hit);
    assert_eq!(row_count(&db, TARGET), 2);
    let conn = rusqlite::Connection::open(&db).unwrap();
    let dedup: i64 = conn
        .query_row("SELECT COUNT(*) FROM notify_dedup", [], |r| r.get(0))
        .expect("notify_dedup table exists");
    assert_eq!(dedup, 0, "absent key writes no dedup row");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_retry_race_yields_one_row_and_one_id_8487() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("s.db");
    let store = Arc::new(SqliteStore::open(&db).unwrap());
    let mut joins = Vec::new();
    for _ in 0..8 {
        let s = Arc::clone(&store);
        joins.push(tokio::spawn(async move {
            deliver(&s, "ai:alice", TARGET, "body", Some(KEY)).await
        }));
    }
    let mut ids = Vec::new();
    let mut fresh = 0;
    for j in joins {
        let o = j.await.unwrap().expect("every racer succeeds");
        if !o.dedup_hit {
            fresh += 1;
        }
        ids.push(o.id);
    }
    assert_eq!(fresh, 1, "exactly one racer inserts");
    assert!(ids.iter().all(|i| *i == ids[0]), "all callers get one id");
    assert_eq!(row_count(&db, TARGET), 1);
}

#[tokio::test]
async fn probe_error_fails_closed_with_nothing_written_8487() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("s.db");
    let store = SqliteStore::open(&db).unwrap();
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("DROP TABLE IF EXISTS notify_dedup;")
            .unwrap();
    }
    let err = deliver(&store, "ai:alice", TARGET, "body", Some(KEY))
        .await
        .expect_err("a probe failure is an error, never 'not seen'");
    assert!(
        !matches!(
            err,
            StoreError::Conflict { .. } | StoreError::InvalidInput { .. }
        ),
        "typed store error, got {err:?}"
    );
    assert_eq!(row_count(&db, TARGET), 0, "nothing written");
    let conn = rusqlite::Connection::open(&db).unwrap();
    let charged: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(current_memories_today), 0) FROM agent_quotas WHERE agent_id = 'ai:alice'",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    assert_eq!(charged, 0, "quota refunded on a failed probe");
}

#[test]
fn digest_field_list_is_pinned_8487() {
    use sha2::{Digest, Sha256};
    // Exactly: target, title, payload, priority (after clamp), tier (after
    // default), each as a u64 big-endian length prefix then the bytes.
    let mut h = Sha256::new();
    for f in [TARGET, "t", "p", "5", "short"] {
        h.update((f.len() as u64).to_be_bytes());
        h.update(f.as_bytes());
    }
    let expected = hex::encode(h.finalize());
    assert_eq!(content_digest(TARGET, "t", "p", 5, &Tier::Short), expected);
    // Every pinned field changes the digest.
    let base = content_digest(TARGET, "t", "p", 5, &Tier::Short);
    assert_ne!(base, content_digest("ai:other", "t", "p", 5, &Tier::Short));
    assert_ne!(base, content_digest(TARGET, "u", "p", 5, &Tier::Short));
    assert_ne!(base, content_digest(TARGET, "t", "q", 5, &Tier::Short));
    assert_ne!(base, content_digest(TARGET, "t", "p", 6, &Tier::Short));
    assert_ne!(base, content_digest(TARGET, "t", "p", 5, &Tier::Long));
    // Length-prefixing: a boundary shift between fields must not collide.
    assert_ne!(
        content_digest(TARGET, "ab", "c", 5, &Tier::Short),
        content_digest(TARGET, "a", "bc", 5, &Tier::Short)
    );
}

#[test]
fn key_validator_bounds_and_charset_8487() {
    assert_eq!(validate_idempotency_key("  abc-1  ").unwrap(), "abc-1");
    assert!(validate_idempotency_key("a").is_ok());
    assert!(validate_idempotency_key(&"k".repeat(128)).is_ok());
    assert!(validate_idempotency_key("").is_err());
    assert!(validate_idempotency_key("   ").is_err());
    assert!(validate_idempotency_key(&"k".repeat(129)).is_err());
    assert!(validate_idempotency_key("a b").is_err());
    assert!(validate_idempotency_key("a/b").is_err());
    let msg = validate_idempotency_key("secret value!")
        .unwrap_err()
        .to_string();
    assert!(
        !msg.contains("secret value"),
        "the refusal never echoes the key: {msg}"
    );
}

fn mcp_params(extra: &Value) -> Value {
    let mut p = json!({"target_agent_id": TARGET, "title": "deploy approval", "payload": "body"});
    for (k, v) in extra.as_object().unwrap() {
        p[k] = v.clone();
    }
    p
}

#[test]
fn mcp_handler_dedups_conflicts_and_validates_8487() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("m.db");
    let conn = ai_memory::db::open(&db).expect("open db");
    let ttl = ai_memory::config::ResolvedTtl::default();
    let call = |p: &Value| ai_memory::mcp::handle_notify(&conn, &db, p, &ttl, Some("client-8487"));

    let plain = call(&mcp_params(&json!({}))).expect("no key");
    assert_eq!(
        plain["dedup_hit"],
        json!(false),
        "absent key still reports dedup_hit"
    );
    let a = call(&mcp_params(&json!({"idempotency_key": KEY}))).expect("first");
    let b = call(&mcp_params(&json!({"idempotency_key": KEY}))).expect("retry");
    assert_eq!(a["dedup_hit"], json!(false));
    assert_eq!(b["dedup_hit"], json!(true));
    assert_eq!(a["id"], b["id"]);
    let err = call(&mcp_params(
        &json!({"idempotency_key": KEY, "payload": "other"}),
    ))
    .expect_err("conflict");
    assert!(
        err.contains(a["id"].as_str().unwrap()),
        "conflict names original id: {err}"
    );
    let bad = call(&mcp_params(&json!({"idempotency_key": "has space"}))).expect_err("invalid");
    assert!(!bad.contains("has space"), "never echoes the key: {bad}");
    assert_eq!(row_count(&db, TARGET), 2, "plain + keyed row only");
}

#[test]
fn mcp_schema_names_the_idempotency_key_field_8487() {
    let tools = ai_memory::mcp::tool_definitions();
    let notify = tools["tools"]
        .as_array()
        .expect("tool list")
        .iter()
        .find(|t| t["name"] == "memory_notify")
        .expect("memory_notify listed");
    let prop = &notify["inputSchema"]["properties"]["idempotency_key"];
    assert!(
        prop.is_object(),
        "idempotency_key is in the schema: {notify}"
    );
    assert!(
        prop["description"].as_str().is_some_and(|d| !d.is_empty()),
        "described"
    );
    assert_ne!(
        notify["inputSchema"]["additionalProperties"],
        json!(false),
        "never deny_unknown_fields (#1052)"
    );
}

fn cli(root: &Path, sender: &str) -> Command {
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
        .env("AI_MEMORY_AGENT_ID", sender)
        .args([
            "--db",
            root.join("t.db").to_str().unwrap(),
            "--agent-id",
            sender,
        ]);
    cmd
}

fn cli_notify(root: &Path, payload: &str, key: Option<&str>) -> std::process::Output {
    let mut c = cli(root, "ai:alice");
    c.args([
        "notify",
        "--target-agent-id",
        TARGET,
        "--title",
        "deploy approval",
        "--payload",
        payload,
        "--json",
    ]);
    if let Some(k) = key {
        c.args(["--idempotency-key", k]);
    }
    c.output().unwrap()
}

fn json_of(out: &std::process::Output) -> Value {
    let text = String::from_utf8_lossy(&out.stdout);
    let start = text.find('{').expect("JSON on stdout");
    serde_json::from_str(&text[start..]).expect("parse JSON")
}

#[test]
fn cli_flag_dedups_and_reports_dedup_hit_8487() {
    let root = tempfile::tempdir().unwrap();
    let a = cli_notify(root.path(), "body", Some(KEY));
    assert!(a.status.success(), "{}", String::from_utf8_lossy(&a.stderr));
    let b = cli_notify(root.path(), "body", Some(KEY));
    assert!(b.status.success(), "{}", String::from_utf8_lossy(&b.stderr));
    let (ja, jb) = (json_of(&a), json_of(&b));
    assert_eq!(ja["dedup_hit"], json!(false));
    assert_eq!(jb["dedup_hit"], json!(true));
    assert_eq!(ja["id"], jb["id"]);
    assert_eq!(row_count(&root.path().join("t.db"), TARGET), 1);
    let c = cli_notify(root.path(), "changed", Some(KEY));
    assert!(!c.status.success(), "conflict is a non-zero exit");
    assert!(String::from_utf8_lossy(&c.stderr).contains(ja["id"].as_str().unwrap()));
    let d = cli_notify(root.path(), "body", None);
    assert_eq!(json_of(&d)["dedup_hit"], json!(false));
}
