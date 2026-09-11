// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3587 U3 — curator stale-ruling sweep (SQLite).
//!
//! The unit's core guarantee: the sweep NEVER writes to the ruling rows it
//! inspects (`version` / `updated_at` unchanged, `archived_memories` delta 0).
//! It emits at most ONE `Tier::Short` digest per stale-id-set hash to
//! `[curator].notify_agent_id`, and none at all when that recipient is unset
//! or the cycle is a dry run. The sender is always the curator's own resolved
//! id, never the configured recipient (audit-A F8/F12/F13/F14).

use ai_memory::curator::{CuratorConfig, STALE_RULING_REPORT_TOP_N, run_stale_ruling_sweep};
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use serde_json::json;

const ORDINARY_NS: &str = "proj/rulings-3587";
const RECIPIENT: &str = "ai:fable";

fn open_db() -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::Builder::new()
        .prefix("ai-memory-3587-")
        .tempdir()
        .expect("tempdir");
    let path = dir.path().join("m.db");
    drop(ai_memory::db::open(&path).expect("init"));
    let conn = ai_memory::db::open(&path).expect("open");
    (dir, conn)
}

/// Seed a memory; `age_days` backdates `created_at` AND `updated_at`.
fn seed(
    conn: &rusqlite::Connection,
    tags: &[&str],
    key: Option<&str>,
    extra_meta: serde_json::Value,
    age_days: i64,
) -> String {
    let ts = (chrono::Utc::now() - chrono::Duration::days(age_days)).to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    let mut metadata = json!({"agent_id": "ai:fable"});
    if let Some(k) = key {
        metadata["ruling_key"] = json!(k);
    }
    if let serde_json::Value::Object(m) = extra_meta {
        for (k, v) in m {
            metadata[k] = v;
        }
    }
    let mem = Memory {
        id: id.clone(),
        tier: Tier::Long,
        namespace: ORDINARY_NS.to_string(),
        title: format!("ruling {id}"),
        content: "a ruling body".to_string(),
        tags: tags.iter().map(|t| (*t).to_string()).collect(),
        priority: 5,
        confidence: 1.0,
        source: "test-3587".to_string(),
        created_at: ts.clone(),
        updated_at: ts,
        metadata,
        memory_kind: MemoryKind::Decision,
        confidence_source: ConfidenceSource::CallerProvided,
        version: 1,
        ..Memory::default()
    };
    ai_memory::db::insert(conn, &mem).expect("db::insert");
    id
}

fn cfg(notify: Option<&str>, dry_run: bool) -> CuratorConfig {
    CuratorConfig {
        dry_run,
        stale_ruling_days: 14,
        notify_agent_id: notify.map(str::to_string),
        ..CuratorConfig::default()
    }
}

fn inbox_count(conn: &rusqlite::Connection) -> i64 {
    let ns = ai_memory::inbox_namespace(RECIPIENT);
    conn.query_row(
        "SELECT COUNT(*) FROM memories WHERE namespace = ?1",
        [&ns],
        |r| r.get(0),
    )
    .expect("count inbox")
}

fn snapshot(conn: &rusqlite::Connection, id: &str) -> (i64, String) {
    conn.query_row(
        "SELECT version, updated_at FROM memories WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .expect("snapshot ruling")
}

fn archived_count(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM archived_memories", [], |r| r.get(0))
        .expect("count archived")
}

#[test]
fn stale_ruling_sweep_writes_nothing_to_the_rulings_3587() {
    let (_dir, conn) = open_db();
    let id = seed(&conn, &["ruling"], Some("k-write"), json!({}), 30);
    let before = snapshot(&conn, &id);
    let archived_before = archived_count(&conn);

    let report = run_stale_ruling_sweep(&conn, &cfg(None, false), None).expect("sweep");

    assert!(
        report.stale_rulings_found >= 1,
        "the seeded ruling is stale"
    );
    assert_eq!(
        snapshot(&conn, &id),
        before,
        "ruling version/updated_at drift"
    );
    assert_eq!(
        archived_count(&conn),
        archived_before,
        "sweep must not archive anything"
    );
}

#[test]
fn stale_ruling_digest_not_sent_when_notify_agent_id_unset_3587() {
    let (_dir, conn) = open_db();
    seed(&conn, &["ruling"], Some("k-norecipient"), json!({}), 30);

    let report = run_stale_ruling_sweep(&conn, &cfg(None, false), None).expect("sweep");

    assert!(report.stale_rulings_found >= 1);
    assert_eq!(report.stale_rulings_notified, 0);
    assert_eq!(inbox_count(&conn), 0, "no recipient => no digest");
}

#[test]
fn stale_ruling_dry_run_sends_nothing_3587() {
    let (_dir, conn) = open_db();
    seed(&conn, &["ruling"], Some("k-dry"), json!({}), 30);

    let report = run_stale_ruling_sweep(&conn, &cfg(Some(RECIPIENT), true), None).expect("sweep");

    assert!(report.stale_rulings_found >= 1);
    assert_eq!(report.stale_rulings_notified, 0);
    assert_eq!(inbox_count(&conn), 0, "dry run must not write a digest");
}

#[test]
fn stale_ruling_notify_sender_is_the_curator_not_the_config_value_3587() {
    let (_dir, conn) = open_db();
    seed(&conn, &["ruling"], Some("k-sender"), json!({}), 30);

    let report = run_stale_ruling_sweep(&conn, &cfg(Some(RECIPIENT), false), None).expect("sweep");
    assert_eq!(report.stale_rulings_notified, 1);

    let ns = ai_memory::inbox_namespace(RECIPIENT);
    let sender: String = conn
        .query_row(
            "SELECT json_extract(metadata, '$.agent_id') FROM memories \
             WHERE namespace = ?1 ORDER BY created_at DESC LIMIT 1",
            [&ns],
            |r| r.get(0),
        )
        .expect("digest sender");
    assert_eq!(
        sender, "ai:curator",
        "sender must be the curator, never the recipient"
    );
    assert_ne!(sender, RECIPIENT);
}

#[test]
fn stale_ruling_digest_sent_once_per_sweep_3587() {
    let (_dir, conn) = open_db();
    // Several stale rulings, ONE digest.
    for i in 0..4 {
        seed(
            &conn,
            &["ruling"],
            Some(&format!("k-once-{i}")),
            json!({}),
            30,
        );
    }

    let r1 = run_stale_ruling_sweep(&conn, &cfg(Some(RECIPIENT), false), None).expect("sweep 1");
    let r2 = run_stale_ruling_sweep(&conn, &cfg(Some(RECIPIENT), false), None).expect("sweep 2");
    let r3 = run_stale_ruling_sweep(&conn, &cfg(Some(RECIPIENT), false), None).expect("sweep 3");

    assert_eq!(r1.stale_rulings_notified, 1, "first sweep digests once");
    assert_eq!(r2.stale_rulings_notified, 0, "unchanged set inside floor");
    assert_eq!(r3.stale_rulings_notified, 0, "unchanged set inside floor");
    assert_eq!(
        inbox_count(&conn),
        1,
        "exactly one digest row for N rulings"
    );
}

#[test]
fn stale_ruling_report_list_is_capped_3587() {
    let (_dir, conn) = open_db();
    let n = STALE_RULING_REPORT_TOP_N + 5;
    for i in 0..n {
        // Tag-only rulings (no key) so none is collapsed as a same-key loser.
        let age = 30_i64 + i64::try_from(i).unwrap_or(0);
        seed(&conn, &["ruling"], None, json!({}), age);
    }

    let report = run_stale_ruling_sweep(&conn, &cfg(None, false), None).expect("sweep");

    assert_eq!(report.stale_rulings_found, n);
    assert_eq!(
        report.stale_ruling_ids.len(),
        STALE_RULING_REPORT_TOP_N,
        "persisted id list is capped"
    );
    assert_eq!(
        report.stale_ruling_ids_all.len(),
        n,
        "the full list is available for --json"
    );
}

#[test]
fn ruling_with_verified_marker_is_not_stale_3587() {
    let (_dir, conn) = open_db();
    let id = seed(
        &conn,
        &["ruling"],
        Some("k-verified"),
        json!({ "verified_at": chrono::Utc::now().to_rfc3339() }),
        30,
    );

    let report = run_stale_ruling_sweep(&conn, &cfg(None, false), None).expect("sweep");
    assert!(
        !report.stale_ruling_ids_all.contains(&id),
        "verified ruling is not stale"
    );
}

#[test]
fn ruling_with_superseded_marker_is_not_stale_3587() {
    let (_dir, conn) = open_db();
    let id = seed(
        &conn,
        &["ruling"],
        Some("k-superseded"),
        json!({ "superseded_id": "prior" }),
        30,
    );

    let report = run_stale_ruling_sweep(&conn, &cfg(None, false), None).expect("sweep");
    assert!(
        !report.stale_ruling_ids_all.contains(&id),
        "a superseding ruling is not stale"
    );
}

#[test]
fn stale_ruling_keyed_latest_only_3587() {
    let (_dir, conn) = open_db();
    let older = seed(&conn, &["ruling"], Some("k-latest"), json!({}), 40);
    let newer = seed(&conn, &["ruling"], Some("k-latest"), json!({}), 30);

    let report = run_stale_ruling_sweep(&conn, &cfg(None, false), None).expect("sweep");

    assert!(
        report.stale_ruling_ids_all.contains(&newer),
        "latest for the key is stale"
    );
    assert!(
        !report.stale_ruling_ids_all.contains(&older),
        "older same-key row is superseded history, not stale"
    );
}

#[test]
fn stale_rulings_flag_is_exclusive_and_parses_3587() {
    use ai_memory::daemon_runtime::{Cli, Command};
    use clap::Parser;

    let cli = Cli::try_parse_from(["ai-memory", "curator", "--stale-rulings", "--json"])
        .expect("--stale-rulings parses");
    match cli.command {
        Command::Curator(args) => {
            assert!(args.stale_rulings);
            assert!(args.json);
        }
        _ => panic!("expected the curator subcommand"),
    }

    for conflicting in ["--once", "--daemon", "--prune-reports", "--reflect"] {
        assert!(
            Cli::try_parse_from(["ai-memory", "curator", "--stale-rulings", conflicting]).is_err(),
            "--stale-rulings must conflict with {conflicting}"
        );
    }
}

/// End-to-end: the `curator --stale-rulings` one-shot drives the SAME pass
/// through the real binary and prints the counts (the `--json` full id list
/// included).
#[test]
fn stale_rulings_cli_oneshot_reports_3587() {
    use std::io::Write as _;
    use std::process::{Command as StdCommand, Stdio};

    let dir = tempfile::Builder::new()
        .prefix("ai-memory-3587-cli-")
        .tempdir()
        .expect("tempdir");
    let db = dir.path().join("m.db");

    // Seed one stale, un-superseded ruling through the library connection.
    {
        let conn = ai_memory::db::open(&db).expect("init");
        seed(&conn, &["ruling"], Some("k-cli"), json!({}), 30);
    }

    let mut child = StdCommand::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .arg("--db")
        .arg(&db)
        .arg("--agent-id")
        .arg("test-agent-3587")
        .args(["curator", "--stale-rulings", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ai-memory");
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(b"")
        .expect("close stdin");
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "curator --stale-rulings failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("--json report is JSON");
    assert!(
        report["stale_rulings_found"].as_u64().unwrap_or(0) >= 1,
        "the seeded ruling must be reported: {report}"
    );
}
