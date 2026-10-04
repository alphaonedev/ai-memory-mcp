// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4044 — the CLI stopper-signed enforcement anchor must name the policy
//! that EVALUATED the deny, not one committed after the evaluation.
//!
//! Driven black-box through the real `ai-memory governance check-action
//! --from-pretool-stdin` binary, so the key-dir env vars are set on the CHILD
//! only (no in-process env mutation). The race is made deterministic with a
//! SQLite trigger on the governance DB: the first non-policy `signed_events`
//! row the check appends (the verdict audit row, written after the rules are
//! evaluated) advances the policy sequence in the same connection, exactly the
//! "signed rule change lands mid-check" window. Pre-fix the stopper anchor
//! re-read the policy after evaluation and named P1; post-fix it binds the
//! policy read in the evaluating snapshot (P0).
//!
//! SQLite-only: governance rules live only in the sqlite governance DB.

#![allow(clippy::missing_panics_doc)]

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use ai_memory::governance::audit as roles;
use ai_memory::governance::policy_version::current_policy_version;
use ai_memory::governance::rules_store::{self, Rule};
use ai_memory::signed_events::event_types::GOVERNANCE_POLICY_ADVANCED;

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

fn deny_rule() -> Rule {
    Rule {
        id: "R-4044-fs".to_string(),
        kind: "filesystem_write".to_string(),
        matcher: r#"{"glob":"/deny4044/**"}"#.to_string(),
        severity: "refuse".to_string(),
        reason: "stopper anchor race".to_string(),
        namespace: "_global".to_string(),
        created_by: "operator".to_string(),
        created_at: 1,
        enabled: true,
        signature: None,
        attest_level: "unsigned".to_string(),
    }
}

fn policy_of(conn: &rusqlite::Connection, condition_type: &str) -> (i64, String) {
    let res: String = conn
        .query_row(
            "SELECT resolution FROM checkpoints WHERE condition_type = ?1",
            [condition_type],
            |r| r.get(0),
        )
        .unwrap_or_else(|e| panic!("exactly one {condition_type} checkpoint: {e}"));
    let w: serde_json::Value = serde_json::from_str(&res).expect("resolution json");
    (
        w["policy_seq"].as_i64().expect("policy_seq"),
        w["policy_digest_hex"]
            .as_str()
            .expect("policy_digest_hex")
            .to_string(),
    )
}

fn enrol(dir: &Path, label: &str) -> std::path::PathBuf {
    let d = dir.join(label);
    key_dir_sandbox::mkdir_0700(&d);
    let kp = ai_memory::identity::keypair::generate(label).expect("generate key");
    ai_memory::identity::keypair::save(&kp, &d).expect("save key");
    d
}

/// RED on the pre-fix base: the anchor named the post-evaluation policy P1.
#[test]
fn stopper_anchor_names_the_evaluating_policy_4044() {
    let root = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(".local-runs")
        .join("stopper-anchor-race-4044");
    std::fs::create_dir_all(&root).expect("root");
    let dir = tempfile::Builder::new()
        .prefix("s-")
        .tempdir_in(&root)
        .expect("tempdir");
    let judge_dir = enrol(dir.path(), roles::JUDGE_KEY_LABEL);
    let stopper_dir = enrol(dir.path(), roles::STOPPER_KEY_LABEL);
    let recorder_dir = dir.path().join("recorder");
    key_dir_sandbox::mkdir_0700(&recorder_dir);
    let fake_home = dir.path().join("home");
    std::fs::create_dir_all(&fake_home).expect("home");

    let db = dir.path().join("gov.db");
    let conn = ai_memory::db::open(&db).expect("open");
    rules_store::insert_signed(
        &conn,
        &deny_rule(),
        &ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]),
        "operator",
    )
    .expect("P0 rule");
    let p0 = current_policy_version(&conn).expect("p0");
    // One-shot seam: the first verdict audit row advances the policy sequence.
    conn.execute_batch(&format!(
        "CREATE TABLE race_once_4044 (x INTEGER);
         CREATE TRIGGER race_4044 AFTER INSERT ON signed_events
         WHEN NEW.event_type <> '{GOVERNANCE_POLICY_ADVANCED}'
              AND (SELECT COUNT(*) FROM race_once_4044) = 0
         BEGIN
           INSERT INTO race_once_4044 VALUES (1);
           INSERT INTO signed_events (id, agent_id, event_type, payload_hash, timestamp)
           VALUES ('race-4044', 'operator', '{GOVERNANCE_POLICY_ADVANCED}',
                   zeroblob(32), '2026-01-01T00:00:00Z');
         END;"
    ))
    .expect("install race seam");

    let mut child = Command::new(env!("CARGO_BIN_EXE_ai-memory"))
        .env("AI_MEMORY_NO_CONFIG", "1")
        .env("HOME", &fake_home)
        .env("XDG_CONFIG_HOME", fake_home.join(".config"))
        .env_remove("AI_MEMORY_OPERATOR_PUBKEY")
        .env(roles::JUDGE_KEY_DIR_ENV, &judge_dir)
        .env(roles::STOPPER_KEY_DIR_ENV, &stopper_dir)
        .env(roles::RECORDER_KEY_DIR_ENV, &recorder_dir)
        .args([
            "--db",
            db.to_str().expect("utf-8 db path"),
            "governance",
            "check-action",
            "--from-pretool-stdin",
            "--agent-id",
            "ai:4044",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ai-memory");
    let event = serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_input": { "file_path": "/deny4044/a/b.txt", "content": "x" }
    });
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(event.to_string().as_bytes())
        .expect("write event");
    let out = child.wait_with_output().expect("child output");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "check-action failed: {stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("expected hook JSON; got {stdout:?}: {e} ({stderr})"));
    let hook = &v["hookSpecificOutput"];
    assert_eq!(hook["permissionDecision"], "deny", "P0 refuses: {v}");
    assert!(hook["stopperSig"].is_string(), "stopper anchor signed: {v}");

    let fired: i64 = conn
        .query_row("SELECT COUNT(*) FROM race_once_4044", [], |r| r.get(0))
        .expect("seam count");
    assert_eq!(fired, 1, "the concurrent policy advance fired mid-check");
    let p1 = current_policy_version(&conn).expect("p1");
    assert_eq!(
        p1.seq,
        p0.seq + 1,
        "the concurrent change advanced the policy"
    );

    let enf = policy_of(&conn, "governance_enforcement");
    let ver = policy_of(&conn, "governance_verdict");
    assert_eq!(
        enf,
        (p0.seq, p0.digest_hex()),
        "the stopper anchor must name the EVALUATING policy P0, not P1"
    );
    assert_eq!(ver, enf, "verdict and stopper anchor name one policy");
}
