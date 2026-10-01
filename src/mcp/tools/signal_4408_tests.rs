// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4408: the MCP `memory_signal_send` handler refuses an invalid `to_agent`
//! with the fixed, non-echoing refusal before any hook, sign, quota charge,
//! insert or audit record. The integration cells for the other funnels live in
//! `tests/signal_recipient_validation_4408.rs`.

use super::*;
use serde_json::json;

const NS: &str = "ns4408";
const GOOD_TARGET: &str = "ai:recipient-4408";

fn invalid_targets() -> Vec<(&'static str, String)> {
    vec![
        ("empty", String::new()),
        ("blank", "   ".to_owned()),
        ("overlong_129", "a".repeat(129)),
        ("overlong_64k", "z".repeat(64 * 1024)),
        ("control_chars", "ai:ctl\u{7}\u{1b}ECHOPROBE4408".to_owned()),
        ("nul", "ai:nul\0ECHOPROBE4408".to_owned()),
        ("zero_width", "ai:zw\u{200b}ECHOPROBE4408".to_owned()),
        (
            "reserved",
            crate::identity::sentinels::SYSTEM_PRINCIPAL.to_owned(),
        ),
        ("path_traversal", "ai:../../etc/ECHOPROBE4408".to_owned()),
    ]
}

fn assert_no_echo(label: &str, target: &str, text: &str) {
    if target.trim().is_empty() {
        return;
    }
    assert!(!text.contains(target), "{label}: refusal echoed the target");
    for probe in ["ECHOPROBE4408", "\u{200b}", "system"] {
        if target.contains(probe) {
            assert!(!text.contains(probe), "{label}: refusal echoed `{probe}`");
        }
    }
}

fn assert_no_charge_no_audit(conn: &rusqlite::Connection, sender: &str, label: &str) {
    let q = crate::quotas::get_status(conn, sender, NS).expect("quota status");
    assert_eq!(q.current_storage_bytes, 0, "{label}: quota bytes charged");
    assert_eq!(q.current_memories_today, 0, "{label}: quota charged");
    let audits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM signed_events WHERE event_type = ?1",
            [crate::coordination_audit::SIGNAL_SEND],
            |r| r.get(0),
        )
        .expect("audit count");
    assert_eq!(audits, 0, "{label}: a coordination audit row was written");
}

fn mcp_fixture() -> (rusqlite::Connection, crate::identity::keypair::AgentKeypair) {
    let conn = crate::db::open(std::path::Path::new(":memory:")).expect("fixture db");
    let kp = crate::identity::keypair::generate("ai:mcp4408").expect("keypair");
    (conn, kp)
}

fn mcp_params(to: &Value) -> Value {
    json!({"namespace": NS, "subject": "s4408", "to_agent": to, "body": {"k": "v4408"}})
}

#[test]
fn sqlite_mcp_signal_send_refuses_invalid_recipient_without_echo_4408() {
    let (conn, kp) = mcp_fixture();
    for (label, target) in invalid_targets() {
        let err = crate::mcp::handle_signal_send(&conn, &mcp_params(&json!(target)), Some(&kp))
            .expect_err(label);
        assert_eq!(err, crate::validate::SIGNAL_RECIPIENT_REFUSAL, "{label}");
        assert_no_echo(label, &target, &err);
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM signals", [], |r| r.get(0))
            .expect("rows");
        assert_eq!(rows, 0, "{label}: a signal row was persisted");
        assert_no_charge_no_audit(&conn, &kp.agent_id, label);
    }
}

/// A present-but-non-string recipient is refused, never silently turned into
/// a namespace broadcast.
#[test]
fn sqlite_mcp_signal_send_refuses_non_string_recipient_4408() {
    let (conn, kp) = mcp_fixture();
    for bad in [json!(42), json!(true), json!(["ai:x"]), json!({"a": 1})] {
        let err = crate::mcp::handle_signal_send(&conn, &mcp_params(&bad), Some(&kp))
            .expect_err("non-string recipient refused");
        assert_eq!(err, crate::validate::SIGNAL_RECIPIENT_REFUSAL);
    }
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM signals", [], |r| r.get(0))
        .expect("rows");
    assert_eq!(rows, 0);
}

/// A `pre_signal_send` rewrite cannot smuggle an invalid recipient past the
/// handler: the final recipient is re-validated before sign / charge / insert.
#[test]
fn sqlite_mcp_hook_modified_recipient_is_revalidated_4408() {
    let (conn, kp) = mcp_fixture();
    let hooks = SignalHooks {
        pre_signal_send: Some(Box::new(|d| {
            let mut d = d.clone();
            d.to_agent = Some("ai:bad\u{200b}ECHOPROBE4408".to_owned());
            SignalHookDecision::Modify(Box::new(d))
        })),
        post_signal_ack: None,
    };
    let err = crate::mcp::handle_signal_send_with_hooks(
        &conn,
        &mcp_params(&json!(GOOD_TARGET)),
        Some(&kp),
        &hooks,
    )
    .expect_err("modified recipient refused");
    assert_eq!(err, crate::validate::SIGNAL_RECIPIENT_REFUSAL);
    assert_no_charge_no_audit(&conn, &kp.agent_id, "hook_modify");
}

/// The recipient is counted in the #1807 storage-only quota bytes (MCP).
#[test]
fn sqlite_mcp_recipient_is_counted_in_quota_bytes_4408() {
    let (conn, kp) = mcp_fixture();
    let to = "ai:quota-recipient-4408";
    crate::mcp::handle_signal_send(&conn, &mcp_params(&json!(to)), Some(&kp)).expect("direct send");
    let with_to = crate::quotas::get_status(&conn, &kp.agent_id, NS)
        .expect("status")
        .current_storage_bytes;
    let (conn2, kp2) = mcp_fixture();
    let mut p = mcp_params(&json!(null));
    p["to_agent"] = Value::Null;
    crate::mcp::handle_signal_send(&conn2, &p, Some(&kp2)).expect("broadcast");
    let without = crate::quotas::get_status(&conn2, &kp2.agent_id, NS)
        .expect("status")
        .current_storage_bytes;
    let delta = i64::try_from(to.len()).expect("len");
    assert_eq!(with_to - without, delta, "recipient bytes not counted");
}
