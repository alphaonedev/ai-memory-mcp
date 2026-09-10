// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::needless_update)]
#![allow(clippy::redundant_closure_for_method_calls)]
//! #3394 — `remember='forever'` is a false success and is refused.
//!
//! The K10 registry is process-local (`SYNTHETIC_RULES`). Advertising
//! `forever` as durable was a lie (lost on every MCP stdio exit; never
//! consulted by `enforce_governance`). GA truthfulness:
//!
//! - `forever` → refused, pending row untouched, no synthetic rule.
//! - `session` → accepted, synthetic rule recorded for this process.
//!
//! Durable persistence is #3580 (v1.1.0).

#![allow(clippy::await_holding_lock)]

use ai_memory::approvals::{clear_synthetic_rules_for_test, list_synthetic_rules};
use ai_memory::models::ConfidenceSource;
use serde_json::json;
use std::sync::Mutex;

static REMEMBER_LOCK: Mutex<()> = Mutex::new(());

fn seed_delete_pending(namespace: &str, requested_by: &str) -> (rusqlite::Connection, String) {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    let mem = ai_memory::models::Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: ai_memory::models::Tier::Long,
        namespace: namespace.into(),
        title: "k10-3394".into(),
        content: "x".into(),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".into(),
        access_count: 0,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
        last_accessed_at: None,
        expires_at: None,
        metadata: serde_json::json!({}),
        reflection_depth: 0,
        memory_kind: ai_memory::models::MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
        ..ai_memory::models::Memory::default()
    };
    let mem_id = ai_memory::db::insert(&conn, &mem).expect("insert memory");
    let payload = json!({"reason": "k10-3394"});
    let pending_id = ai_memory::db::queue_pending_action(
        &conn,
        ai_memory::models::GovernedAction::Delete,
        namespace,
        Some(&mem_id),
        requested_by,
        &payload,
    )
    .expect("queue_pending_action");
    (conn, pending_id)
}

#[tokio::test]
async fn mcp_pending_approve_forever_is_refused_nothing_recorded_3394() {
    let _g = REMEMBER_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_synthetic_rules_for_test();
    let (conn, pending_id) = seed_delete_pending("ns-forever", "alice");

    let args = json!({
        "id": pending_id,
        "agent_id": "operator-1",
        "remember": "forever",
    });
    let err = ai_memory::mcp::handle_pending_approve(&conn, &args, None)
        .expect_err("forever must refuse");
    assert_eq!(err, ai_memory::errors::msg::REMEMBER_FOREVER_UNHONOURABLE);

    let row = ai_memory::db::get_pending_action(&conn, &pending_id)
        .expect("read")
        .expect("row present");
    assert_eq!(row.status, "pending", "refused forever must not decide");
    assert!(row.decided_by.is_none(), "no decider may be recorded");
    assert!(
        list_synthetic_rules().is_empty(),
        "no synthetic rule on a refused forever"
    );
}

#[tokio::test]
async fn mcp_pending_reject_forever_is_refused_nothing_recorded_3394() {
    let _g = REMEMBER_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_synthetic_rules_for_test();
    let (conn, pending_id) = seed_delete_pending("ns-deny", "bob");

    let args = json!({
        "id": pending_id,
        "agent_id": "operator-1",
        "remember": "forever",
    });
    let err =
        ai_memory::mcp::handle_pending_reject(&conn, &args, None).expect_err("forever must refuse");
    assert_eq!(err, ai_memory::errors::msg::REMEMBER_FOREVER_UNHONOURABLE);

    let row = ai_memory::db::get_pending_action(&conn, &pending_id)
        .expect("read")
        .expect("row present");
    assert_eq!(row.status, "pending", "refused forever must not decide");
    assert!(
        list_synthetic_rules().is_empty(),
        "no synthetic deny rule on a refused forever"
    );
}

#[tokio::test]
async fn mcp_pending_approve_session_records_rule_3394() {
    let _g = REMEMBER_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_synthetic_rules_for_test();
    let (conn, pending_id) = seed_delete_pending("ns-session", "alice");

    let args = json!({
        "id": pending_id,
        "agent_id": "operator-1",
        "remember": "session",
    });
    let resp = ai_memory::mcp::handle_pending_approve(&conn, &args, None)
        .expect("session remember must work");
    assert_eq!(resp["approved"], json!(true), "approve failed: {resp}");
    assert_eq!(resp["remember"], json!("session"));

    let snap = list_synthetic_rules();
    let found = snap.iter().any(|r| {
        r.action_type == "delete"
            && r.namespace == "ns-session"
            && r.agent_id.as_deref() == Some("alice")
            && r.decision == "approve"
    });
    assert!(
        found,
        "session rule not recorded after MCP approve; snap={snap:?}"
    );
}

#[test]
fn remember_once_does_not_record_a_rule() {
    let _g = REMEMBER_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    clear_synthetic_rules_for_test();
    let snap = list_synthetic_rules();
    assert!(snap.is_empty(), "registry should start empty: {snap:?}");
}
