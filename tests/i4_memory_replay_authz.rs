// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown)]
//! v0.7.0 #628 I4 (review blocker H6) — `memory_replay` authorisation.
//!
//! Before this fix `memory_replay` fetched and decompressed transcript
//! content with no permission check, leaking verbatim chat content
//! across tenant boundaries on a multi-agent daemon. The fix routes
//! the read through the K9 unified evaluator
//! ([`ai_memory::permissions::Permissions::evaluate`]) using the new
//! [`ai_memory::permissions::Op::MemoryReplay`] variant; a Deny
//! decision short-circuits before the BLOB ever leaves SQLite.
//!
//! Scenario covered:
//!
//! * Agent A stores a transcript in namespace `tenant-a/`. Agent B
//!   issues `memory_replay` against the memory linked to it. The K9
//!   ruleset denies cross-tenant reads; the test asserts B receives
//!   an error AND no transcript content reaches B's response payload.

use ai_memory::db;
use ai_memory::mcp;
use ai_memory::permissions::{
    self, PermissionRule, RuleDecision, clear_active_permission_rules_for_test,
    set_active_permission_rules,
};
use ai_memory::transcripts;
use rusqlite::params;
use serde_json::json;
use std::sync::Mutex;

/// Process-wide gate so the rules registry mutations don't race
/// against other integration tests that also seed `[[permissions.rules]]`.
/// Mirrors the pattern in `tests/identity_e2e.rs`.
static RULES_GUARD: Mutex<()> = Mutex::new(());

/// Insert a stub `memories` row owned by the given `owner_agent_id` in
/// the given namespace. The `owner_agent_id` lands in `metadata.agent_id`
/// so the post-#1075 visibility gate at
/// `src/mcp/tools/replay.rs::handle_replay` can identify the owner.
/// Pre-#1075 this argument was absent (memories had no owner and
/// visibility was unenforced on the replay path) — that's the gap
/// #1075 closed.
fn insert_memory(
    conn: &rusqlite::Connection,
    id: &str,
    namespace: &str,
    owner_agent_id: &str,
) {
    let now = chrono::Utc::now().to_rfc3339();
    // v0.7.0 fix campaign R1-M2 — substrate CHECK trigger enforces
    // tier ∈ {short, mid, long}.
    let metadata = serde_json::json!({"agent_id": owner_agent_id}).to_string();
    conn.execute(
        "INSERT INTO memories (
            id, tier, namespace, title, content, metadata, created_at, updated_at
         ) VALUES (?1, 'short', ?2, ?3, 'body', ?4, ?5, ?5)",
        params![id, namespace, format!("title-{id}"), metadata, now],
    )
    .unwrap();
}

#[test]
fn agent_b_cannot_replay_agent_a_transcript_when_rule_denies() {
    let _g = RULES_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_active_permission_rules_for_test();

    let conn = db::open(std::path::Path::new(":memory:")).unwrap();

    // Agent A's tenant namespace + a memory owned by agent-a + a
    // sensitive transcript anchored to it.
    insert_memory(&conn, "mem-a", "tenant-a/notes", "agent-a");
    let secret = "[user] Agent A's confidential strategy doc — do not leak.";
    let t = transcripts::store(&conn, "tenant-a/notes", secret, None).unwrap();
    transcripts::link_transcript(&conn, "mem-a", &t.id, None, None).unwrap();

    // K9 rule: deny agent-b from replaying tenant-a/**. Kept as belt-
    // and-suspenders even though post-#1075 the visibility gate fires
    // first — if a future refactor inadvertently bypasses #1075, the
    // K9 rule remains the second line of defense.
    set_active_permission_rules(vec![PermissionRule {
        namespace_pattern: "tenant-a/**".to_string(),
        op: "memory_replay".to_string(),
        agent_pattern: "agent-b".to_string(),
        decision: RuleDecision::Deny,
        reason: Some("agent-b cannot read tenant-a transcripts".to_string()),
    }]);

    // Sanity: the new Op variant round-trips through the wire string.
    assert_eq!(
        permissions::Op::from_str("memory_replay"),
        Some(permissions::Op::MemoryReplay),
        "new MemoryReplay variant must be wired into the wire matcher"
    );

    // Agent B issues the replay. Post-#1075 the visibility gate fires
    // BEFORE the K9 permission rules and returns a silent-empty Ok
    // (count: 0, transcripts: []) rather than a Deny error. The empty
    // shape is identical to the "memory does not exist" response, by
    // design — preventing an attacker from probing transcript existence
    // via permission-error vs not-found discrimination. The K9 Deny
    // rule above is still loaded but it's load-bearing only if a
    // future refactor reverts the visibility gate.
    let payload = mcp::handle_replay(
        &conn,
        &json!({
            "memory_id": "mem-a",
            "agent_id": "agent-b",
        }),
        None,
    )
    .expect("post-#1075 replay returns Ok with empty body on visibility-denied");

    assert_eq!(
        payload["count"], 0,
        "agent-b must observe count=0 (silent empty per #1075); got: {payload}"
    );
    let transcripts_arr = payload["transcripts"]
        .as_array()
        .expect("transcripts array present even when empty");
    assert!(
        transcripts_arr.is_empty(),
        "agent-b must observe empty transcripts (post-#1075 anti-enumeration); got: {payload}"
    );
    let raw_payload = payload.to_string();
    assert!(
        !raw_payload.contains(secret),
        "the secret transcript content must NOT leak via the empty response: {payload}"
    );

    clear_active_permission_rules_for_test();
}

#[test]
fn agent_a_can_still_replay_own_namespace_with_same_rule_loaded() {
    let _g = RULES_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    clear_active_permission_rules_for_test();

    let conn = db::open(std::path::Path::new(":memory:")).unwrap();
    insert_memory(&conn, "mem-a", "tenant-a/notes", "agent-a");
    let body = "[user] Agent A's own conversation.";
    let t = transcripts::store(&conn, "tenant-a/notes", body, None).unwrap();
    transcripts::link_transcript(&conn, "mem-a", &t.id, None, None).unwrap();

    // Same rule shape as above: only `agent-b` is denied. `agent-a`
    // (the owner) must not be incidentally locked out by the gate.
    set_active_permission_rules(vec![PermissionRule {
        namespace_pattern: "tenant-a/**".to_string(),
        op: "memory_replay".to_string(),
        agent_pattern: "agent-b".to_string(),
        decision: RuleDecision::Deny,
        reason: Some("agent-b cannot read tenant-a transcripts".to_string()),
    }]);

    let payload = mcp::handle_replay(
        &conn,
        &json!({
            "memory_id": "mem-a",
            "agent_id": "agent-a",
        }),
        None,
    )
    .expect("agent-a must be allowed");
    assert_eq!(payload["count"], 1);
    let transcripts_arr = payload["transcripts"].as_array().unwrap();
    assert_eq!(transcripts_arr.len(), 1);
    assert_eq!(transcripts_arr[0]["content"], body);

    clear_active_permission_rules_for_test();
}
