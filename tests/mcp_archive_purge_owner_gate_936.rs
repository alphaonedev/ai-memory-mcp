// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! Issue #936 — MCP-side `archive_purge` caller-vs-row-owner gate
//! regression.
//!
//! The HTTP path was the headline RCA in #936; the MCP entry at
//! `src/mcp/tools/archive.rs::handle_archive_purge` was a sibling
//! attack surface that pre-fix also reached `db::purge_archive`
//! with no caller and deleted every owner's archive corpus.
//!
//! This regression file pins the MCP-side contract:
//!
//! 1. `mcp_caller_only_purges_own_rows_936` — alice's MCP-tool call
//!    (with `agent_id: "alice"` in params) MUST NOT purge bob's
//!    archived rows.
//! 2. `mcp_as_admin_true_purges_cross_tenant_936` — the explicit
//!    `as_admin: true` operator opt-in restores the owner-blind
//!    wipe for legitimate admin sweeps.
//! 3. `mcp_response_carries_owner_scope_936` — the response
//!    envelope includes `owner_scope: "admin"|"caller"` so the
//!    operator can audit which branch fired.

use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use serde_json::json;
use tempfile::NamedTempFile;

fn open_db_with_seed(owner: &str, namespace: &str) -> NamedTempFile {
    let f = NamedTempFile::new().expect("tempfile");
    let conn = ai_memory::db::open(f.path()).expect("db::open");
    let now = chrono::Utc::now().to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    let mem = Memory {
        id: id.clone(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("seed-{owner}"),
        content: format!("body owned by {owner}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": owner}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };
    ai_memory::db::insert(&conn, &mem).expect("insert seed");
    ai_memory::db::archive_memory(&conn, &id, Some("test-936"))
        .expect("archive_memory must move row");
    f
}

fn add_seed(f: &NamedTempFile, owner: &str, namespace: &str) {
    let conn = ai_memory::db::open(f.path()).expect("reopen db");
    let now = chrono::Utc::now().to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    let mem = Memory {
        id: id.clone(),
        tier: Tier::Long,
        namespace: namespace.to_string(),
        title: format!("seed-{owner}-2"),
        content: format!("body owned by {owner}"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "test".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"agent_id": owner}),
        reflection_depth: 0,
        memory_kind: MemoryKind::Observation,
        entity_id: None,
        persona_version: None,
        citations: Vec::new(),
        source_uri: None,
        source_span: None,
        confidence_source: ConfidenceSource::CallerProvided,
        confidence_signals: None,
        confidence_decayed_at: None,
        version: 1,
    };
    ai_memory::db::insert(&conn, &mem).expect("insert seed");
    ai_memory::db::archive_memory(&conn, &id, Some("test-936"))
        .expect("archive_memory must move row");
}

fn archive_count(f: &NamedTempFile) -> i64 {
    let conn = ai_memory::db::open(f.path()).expect("reopen db");
    conn.query_row("SELECT COUNT(*) FROM archived_memories", [], |r| r.get(0))
        .expect("count")
}

#[test]
fn mcp_caller_only_purges_own_rows_936() {
    let f = open_db_with_seed("alice", "ns-936-mcp/a");
    add_seed(&f, "bob", "ns-936-mcp/b");
    assert_eq!(archive_count(&f), 2);

    let conn = ai_memory::db::open(f.path()).expect("reopen db");
    let resp = ai_memory::mcp::handle_archive_purge_for_test(&conn, &json!({"agent_id": "alice"}))
        .expect("purge");
    assert_eq!(
        resp["purged"].as_u64(),
        Some(1),
        "#936 MCP: alice MUST only purge her own row; got {resp}"
    );
    assert_eq!(
        resp["owner_scope"].as_str(),
        Some("caller"),
        "#936 MCP: response MUST declare owner_scope=caller; got {resp}"
    );
    // bob's row must still be there.
    assert_eq!(
        archive_count(&f),
        1,
        "#936 MCP: bob's archived row MUST survive alice's purge"
    );
}

#[test]
fn mcp_as_admin_true_purges_cross_tenant_936() {
    let f = open_db_with_seed("alice", "ns-936-mcp/a");
    add_seed(&f, "bob", "ns-936-mcp/b");
    assert_eq!(archive_count(&f), 2);

    let conn = ai_memory::db::open(f.path()).expect("reopen db");
    let resp = ai_memory::mcp::handle_archive_purge_for_test(
        &conn,
        &json!({"agent_id": "ops:admin", "as_admin": true}),
    )
    .expect("purge");
    assert_eq!(
        resp["purged"].as_u64(),
        Some(2),
        "#936 MCP: as_admin=true MUST purge cross-tenant; got {resp}"
    );
    assert_eq!(
        resp["owner_scope"].as_str(),
        Some("admin"),
        "#936 MCP: as_admin=true MUST declare owner_scope=admin; got {resp}"
    );
    assert_eq!(archive_count(&f), 0);
}

#[test]
fn mcp_response_carries_owner_scope_936() {
    // Empty DB still returns the envelope with `owner_scope`.
    let f = NamedTempFile::new().expect("tempfile");
    let _ = ai_memory::db::open(f.path()).expect("db::open");
    let conn = ai_memory::db::open(f.path()).expect("reopen db");

    // Default (no as_admin) → caller scope.
    let resp = ai_memory::mcp::handle_archive_purge_for_test(&conn, &json!({"agent_id": "alice"}))
        .expect("purge");
    assert_eq!(
        resp["owner_scope"].as_str(),
        Some("caller"),
        "#936 MCP: default owner_scope MUST be `caller`; got {resp}"
    );

    // Explicit as_admin=true → admin scope.
    let resp = ai_memory::mcp::handle_archive_purge_for_test(
        &conn,
        &json!({"agent_id": "ops:admin", "as_admin": true}),
    )
    .expect("purge");
    assert_eq!(
        resp["owner_scope"].as_str(),
        Some("admin"),
        "#936 MCP: as_admin=true owner_scope MUST be `admin`; got {resp}"
    );
}
