// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Immutability properties:
//!
//! * Non-operator `rule_remove` over MCP is refused (the mutation
//!   tool is NOT registered — dispatch returns "unknown tool").
//! * Operator-signed `rules remove` via the CRUD path succeeds (the
//!   CLI path verifies signature; we exercise the store directly
//!   under unit-test conditions).
//! * The wire-stable `governance.not_available_over_mcp` error
//!   string is exposed for callers that catch + classify.

use ai_memory::governance::rules_store::{self, Rule};
use ai_memory::mcp::handle_rule_list;

fn fresh_conn() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE governance_rules (
             id TEXT PRIMARY KEY,
             kind TEXT NOT NULL,
             matcher TEXT NOT NULL,
             severity TEXT NOT NULL CHECK (severity IN ('refuse','warn','log','escalate')),
             reason TEXT NOT NULL,
             namespace TEXT NOT NULL DEFAULT '_global',
             created_by TEXT NOT NULL,
             created_at INTEGER NOT NULL,
             enabled INTEGER NOT NULL DEFAULT 1,
             signature BLOB,
             attest_level TEXT NOT NULL DEFAULT 'unsigned'
         );",
    )
    .unwrap();
    conn
}

fn insert_rule(conn: &rusqlite::Connection, id: &str) {
    rules_store::insert(
        conn,
        &Rule {
            id: id.into(),
            kind: "bash".into(),
            matcher: r#"{"command_regex":"x"}"#.into(),
            severity: "refuse".into(),
            reason: "test".into(),
            namespace: "_global".into(),
            created_by: "test".into(),
            created_at: 0,
            enabled: true,
            signature: None,
            attest_level: "unsigned".into(),
        },
    )
    .unwrap();
}

#[test]
fn mcp_read_path_lists_rules() {
    let conn = fresh_conn();
    insert_rule(&conn, "R1");
    insert_rule(&conn, "R2");
    let result = handle_rule_list(&conn, &serde_json::json!({})).unwrap();
    assert_eq!(result["count"], 2);
}

#[test]
fn mcp_mutation_disabled_wire_string_is_stable() {
    // The exposed wire string is the contract callers catch. If a
    // future PR registers mutation tools, this string MUST remain
    // their refusal vocabulary (or this test changes deliberately).
    let s = ai_memory::mcp::tools_check_agent_action_mutation_disabled_error();
    assert!(s.starts_with("governance.not_available_over_mcp"));
    assert!(s.contains("CLI"));
    assert!(s.contains("HTTP"));
}

#[test]
fn store_remove_with_no_signature_check_succeeds_at_sql_level() {
    // At the rules_store SQL layer there is NO operator-key gate —
    // gating lives one level up in cli/rules.rs (CLI) and the HTTP
    // handler. This test pins that the SQL layer is symmetric (so a
    // signed-and-verified mutation by the caller flows through
    // unobstructed).
    let conn = fresh_conn();
    insert_rule(&conn, "R1");
    assert!(rules_store::remove(&conn, "R1").unwrap());
    assert_eq!(rules_store::get(&conn, "R1").unwrap(), None);
}

#[test]
fn store_set_enabled_signed_round_trips_and_audits() {
    // v0.9.0 §25.3 S3 (F-40) — the raw `set_enabled` is now internal
    // (pub(crate)); the public, audited path is `set_enabled_signed`,
    // which co-transacts the flip with an operator-signed audit row. This
    // integration test exercises that path end-to-end (a signed_events +
    // governance_rules pair, a deterministic operator key).
    let conn = fresh_conn();
    conn.execute_batch(
        "CREATE TABLE signed_events (
             id TEXT PRIMARY KEY,
             agent_id TEXT NOT NULL,
             event_type TEXT NOT NULL,
             payload_hash BLOB NOT NULL,
             signature BLOB,
             attest_level TEXT NOT NULL DEFAULT 'unsigned',
             timestamp TEXT NOT NULL,
             prev_hash BLOB,
             sequence INTEGER, cause_hash BLOB
         );
         CREATE UNIQUE INDEX idx_signed_events_sequence ON signed_events(sequence);",
    )
    .unwrap();
    insert_rule(&conn, "R1");
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

    assert!(rules_store::set_enabled_signed(&conn, "R1", false, &key, "operator").unwrap());
    let rule = rules_store::get(&conn, "R1").unwrap().unwrap();
    assert!(!rule.enabled);

    assert!(rules_store::set_enabled_signed(&conn, "R1", true, &key, "operator").unwrap());
    let rule = rules_store::get(&conn, "R1").unwrap().unwrap();
    assert!(rule.enabled);

    // Each signed flip left an operator-signed audit row.
    let audit_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events
             WHERE event_type IN ('governance.rule_disabled','governance.rule_enabled')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(audit_rows, 2, "each signed flip audits exactly once");
}

#[test]
fn store_signature_persistence_round_trips() {
    let conn = fresh_conn();
    insert_rule(&conn, "R1");
    let sig = vec![1u8, 2, 3, 4, 5];
    rules_store::update_signature(&conn, "R1", &sig, "operator_signed").unwrap();
    let rule = rules_store::get(&conn, "R1").unwrap().unwrap();
    assert_eq!(rule.signature, Some(sig));
    assert_eq!(rule.attest_level, "operator_signed");
}
