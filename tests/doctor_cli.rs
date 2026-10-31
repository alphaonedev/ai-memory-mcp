// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::zombie_processes)]

//! Phase P7 / R7 — `ai-memory doctor` CLI integration tests.
//!
//! These tests spawn the real `ai-memory` binary (via `assert_cmd`) and
//! exercise the doctor subcommand end-to-end. They cover:
//!
//! - `doctor_reports_clean_on_fresh_db` — a freshly-initialized DB
//!   produces a non-critical report.
//! - `doctor_warns_on_dim_violations` — when the post-P2 `embedding_dim`
//!   column is present and a row's dim disagrees with its namespace's
//!   modal dim, the doctor reports CRITICAL on the Storage section. (We
//!   simulate the post-P2 schema by hand-editing the `SQLite` file; the
//!   real P2 migration lands separately.)
//! - `doctor_critical_on_pending_actions_older_than_24h` — synthesizing
//!   a `pending_actions` row with `requested_at` 25h in the past pushes
//!   Governance into CRITICAL and the process exits 2.
//! - `doctor_remote_queries_capabilities_endpoint` — `--remote <url>`
//!   pulls the Capabilities JSON from a live `serve` daemon and renders
//!   the `recall_mode` / `reranker_active` fields.
//!
//! All tests set `AI_MEMORY_NO_CONFIG=1` per the standard CLI test
//! convention.

use std::path::Path;
use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;

mod common;
use common::tls_serve::spawn_serve;
use rusqlite::params;
use tempfile::TempDir;

#[test]
fn spawn_timeout_is_sixty_seconds_8287() {
    assert_eq!(common::tls_serve::SPAWN_TIMEOUT, Duration::from_secs(60));
}

/// Build the standard `ai-memory --db <tmp>` command shape with
/// `AI_MEMORY_NO_CONFIG=1` set.
fn ai_memory(db: &Path) -> Command {
    let mut cmd = Command::cargo_bin("ai-memory").unwrap();
    // #3198 — the doctor Identity section stats the default key dir. Pin a
    // 0700 sibling of the test DB so the child never sees the host 0o775
    // `~/.config/ai-memory/keys` (self-hosted umask 0002).
    let keys = db
        .parent()
        .expect("db lives in a tempdir")
        .join("keys-3198");
    std::fs::create_dir_all(&keys).expect("mkdir doctor key sandbox");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o700))
            .expect("chmod 0700 doctor key sandbox");
    }
    cmd.env("AI_MEMORY_NO_CONFIG", "1")
        .env("AI_MEMORY_KEY_DIR", &keys)
        .args(["--db", db.to_str().unwrap()]);
    cmd
}

/// Initialize the DB by running an ai-memory command that touches it.
/// We use `stats` because it's a read-only path that triggers
/// `db::open` -> migrations -> close.
fn init_db(db: &Path) {
    ai_memory(db).args(["stats"]).assert().success();
}

#[test]
fn doctor_reports_clean_on_fresh_db() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    init_db(&db);

    // Default invocation — text mode, no --fail-on-warn. Wave-2 B3
    // WARNs on unencrypted-at-rest for a fresh non-sqlcipher db, so
    // overall is WARN (not INFO). Still exits 0 without --fail-on-warn.
    // No section is Critical.
    ai_memory(&db)
        .args(["doctor"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ai-memory doctor"))
        .stdout(predicate::str::contains("Storage"))
        .stdout(predicate::str::contains("Governance"))
        .stdout(predicate::str::contains("Webhook"))
        .stdout(predicate::str::contains("overall:      WARN"));

    // JSON mode produces a parseable document with the expected shape.
    let out = ai_memory(&db)
        .args(["doctor", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["mode"].as_str().unwrap(), "local");
    assert!(v["sections"].is_array());
    let sections = v["sections"].as_array().unwrap();
    assert!(!sections.is_empty(), "expected at least one section");
    // No section should be Critical on a fresh DB.
    for s in sections {
        let sev = s["severity"].as_str().unwrap_or("");
        assert_ne!(
            sev, "critical",
            "fresh DB unexpectedly produced critical section: {s}"
        );
    }
}

#[test]
fn doctor_warns_on_dim_violations() {
    // Simulate the post-P2 schema by manually adding the `embedding_dim`
    // column. Pre-P2 the column doesn't exist and `db::doctor_dim_violations`
    // returns Ok(None) so this test would render N/A. Once P2 lands the
    // column natively the manual ALTER becomes a no-op (the existing column
    // check inside the helper is dim-agnostic).
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    init_db(&db);

    let conn = rusqlite::Connection::open(&db).unwrap();
    let _ = conn.execute("ALTER TABLE memories ADD COLUMN embedding_dim INTEGER", []);

    // Insert two rows in the same namespace with different non-null dims —
    // the modal dim becomes whichever appears most. With one 384 and one
    // 768, the helper picks one as modal (ties broken by ordering) and
    // reports the other as a violation. We insert two 384s and one 768
    // so 384 is the unambiguous mode and the lone 768 is the violation.
    let now = chrono::Utc::now().to_rfc3339();
    for (id, dim) in &[("dim-a", 384_i64), ("dim-b", 384_i64), ("dim-c", 768_i64)] {
        conn.execute(
            "INSERT INTO memories (id, tier, namespace, title, content, tags, priority,
                                   confidence, source, access_count, created_at, updated_at,
                                   embedding, embedding_dim, metadata)
             VALUES (?1, 'long', 'p2-test', ?2, 'content', '[]', 5, 1.0, 'test', 0, ?3, ?3,
                     X'01000000', ?4, '{}')",
            params![id, format!("title-{id}"), now, dim],
        )
        .unwrap();
    }
    drop(conn);

    // The doctor should now flag dim_violations >= 1 and exit 2 (Critical).
    let assert = ai_memory(&db).args(["doctor"]).assert();
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("dim_violations"),
        "expected dim_violations in stdout, got: {stdout}"
    );
    assert!(
        stdout.contains("[CRIT] Storage") || stdout.contains("CRIT"),
        "expected CRIT severity, got: {stdout}"
    );
    // Exit code: 2 (Critical).
    let code = output.status.code().unwrap_or(0);
    assert_eq!(code, 2, "expected exit code 2 (critical), got {code}");
}

#[test]
fn doctor_critical_on_pending_actions_older_than_24h() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    init_db(&db);

    // Insert a `pending_actions` row dated 25 hours in the past.
    let conn = rusqlite::Connection::open(&db).unwrap();
    let twenty_five_hours_ago = (chrono::Utc::now() - chrono::Duration::hours(25)).to_rfc3339();
    conn.execute(
        "INSERT INTO pending_actions (id, action_type, namespace, payload, requested_by,
                                       requested_at, status)
         VALUES ('stale-1', 'store', 'ns', '{}', 'agent', ?1, 'pending')",
        params![twenty_five_hours_ago],
    )
    .unwrap();
    drop(conn);

    let assert = ai_memory(&db).args(["doctor"]).assert();
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Governance"),
        "expected Governance section, got: {stdout}"
    );
    assert!(
        stdout.contains("oldest_pending_age_secs"),
        "expected oldest_pending_age_secs fact, got: {stdout}"
    );
    assert!(
        stdout.contains("CRIT"),
        "expected CRIT severity, got: {stdout}"
    );
    let code = output.status.code().unwrap_or(0);
    assert_eq!(code, 2, "expected exit code 2 (critical), got {code}");
}

#[test]
fn doctor_remote_queries_capabilities_endpoint() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    let serve = spawn_serve(&db, |_| {});

    let assert = ai_memory(&db)
        .args([
            "doctor",
            "--remote",
            &serve.base_url(),
            "--ca-cert",
            serve.tls.cert_path.to_str().unwrap(),
        ])
        .assert();
    let output = assert.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Smoke checks on the rendered text:
    //   - mode is "remote"
    //   - source contains the host URL
    //   - Capabilities section is present and not Critical (the live
    //     daemon reaches the endpoint, so even a v1 schema renders Info)
    assert!(
        stdout.contains("remote mode"),
        "expected 'remote mode', got: {stdout}"
    );
    assert!(
        stdout.contains("Capabilities"),
        "expected Capabilities section, got: {stdout}"
    );
    assert!(
        stdout.contains("schema_version"),
        "expected schema_version fact, got: {stdout}"
    );

    // Should exit 0: the live daemon's capabilities endpoint is reachable
    // and recall_mode_active either matches "hybrid" or is absent (v1
    // schema), neither of which trips a Warning on this clean test daemon.
    let code = output.status.code().unwrap_or(0);
    assert_eq!(code, 0, "expected exit 0 from healthy remote, got {code}");

    // JSON mode parses cleanly.
    let json_out = ai_memory(&db)
        .args([
            "doctor",
            "--remote",
            &serve.base_url(),
            "--ca-cert",
            serve.tls.cert_path.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_slice(&json_out).unwrap();
    assert_eq!(v["mode"].as_str().unwrap(), "remote");
}

/// v1.0.0 #3655 — end-to-end through the binary: a peer whose last ANSWERED
/// pull (`sync_peer_contact`, review rework) is hours old is a stale peer
/// (Critical, exit 2) — its equal-but-old data cursors are the symptom, not
/// the signal; and an unreadable `sync_state` is Critical, never
/// "single-node". Pre-fix the first case rendered Info (|seen - pulled| = 0)
/// and the second rendered N/A with the single-node note.
#[test]
fn doctor_sync_flags_stale_peer_and_unreadable_table_3655() {
    let tmp = TempDir::new().unwrap();
    let db = tmp.path().join("ai-memory.db");
    init_db(&db);
    let old = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute(
            "INSERT INTO sync_state (agent_id, peer_id, last_seen_at, last_pulled_at) \
             VALUES ('me', 'peer-1', ?1, ?1)",
            params![old],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sync_peer_contact (agent_id, peer_id, last_contact_at, \
             catchup_interval_secs) VALUES ('me', 'peer-1', ?1, 60)",
            params![old],
        )
        .unwrap();
    }
    let sync_section = |db: &Path| -> serde_json::Value {
        let out = ai_memory(db)
            .args(["doctor", "--json"])
            .assert()
            .code(2)
            .get_output()
            .stdout
            .clone();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        v["sections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "Sync")
            .cloned()
            .expect("Sync section")
    };
    let fact = |s: &serde_json::Value, key: &str| -> String {
        s["facts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f[0] == key)
            .unwrap_or_else(|| panic!("fact {key} missing in {s}"))[1]
            .as_str()
            .unwrap()
            .to_string()
    };

    let stale = sync_section(&db);
    assert_eq!(stale["severity"], "critical", "{stale}");
    assert_eq!(fact(&stale, "stale_peers"), "1");
    assert_eq!(fact(&stale, "peer::me/peer-1::clock_lead_secs"), "0");
    assert_eq!(
        fact(&stale, "peer::me/peer-1::reachability"),
        "unknown:pull_observation_stale"
    );
    assert!(
        fact(&stale, "peer::me/peer-1::contact_age_secs")
            .parse::<i64>()
            .unwrap()
            >= 7_000
    );

    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("DROP TABLE sync_state;").unwrap();
    }
    let unreadable = sync_section(&db);
    assert_eq!(unreadable["severity"], "critical", "{unreadable}");
    assert_eq!(fact(&unreadable, "sync_state"), "unreadable");
    assert!(
        !unreadable["note"]
            .as_str()
            .unwrap_or_default()
            .contains("single-node deployment or"),
        "{unreadable}"
    );
}
