// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0
//! #1804 (SECURITY) — `kg_timeline` per-target visibility filter regression.
//!
//! Found by the v0.8.0 final 5-agent security review: the #1800 source-owner
//! gate guards WHO may query a memory's link timeline, but the events disclose
//! each linked TARGET's title + namespace. Without a per-target filter, a
//! caller could leak a victim's `scope=private` memory metadata by rooting a
//! link at it and reading the source's timeline. This pins the fix: a
//! non-owner caller must not see a private target's title.

use ai_memory::mcp::handle_kg_timeline;
use ai_memory::models::{Memory, Tier};
use rusqlite::params;
use serde_json::json;

fn mem(id: &str, ns: &str, title: &str, agent: &str, private: bool) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    let meta = if private {
        json!({"agent_id": agent, "scope": "private"})
    } else {
        json!({"agent_id": agent})
    };
    Memory {
        id: id.to_string(),
        tier: Tier::Long,
        namespace: ns.to_string(),
        title: title.to_string(),
        content: format!("{title} body"),
        source: "test".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata: meta,
        ..Memory::default()
    }
}

fn link(conn: &rusqlite::Connection, src: &str, dst: &str) {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO memory_links (source_id, target_id, relation, created_at, valid_from) \
         VALUES (?1, ?2, 'related_to', ?3, ?3)",
        params![src, dst, now],
    )
    .expect("seed link");
}

fn titles(v: &serde_json::Value) -> Vec<String> {
    v["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["title"].as_str().map(str::to_string))
        .collect()
}

#[test]
fn kg_timeline_filters_private_target_from_non_owner_1804() {
    let conn = ai_memory::db::open(std::path::Path::new(":memory:")).unwrap();
    // alice owns source S; bob owns a PRIVATE target T; alice owns target U.
    ai_memory::db::insert(&conn, &mem("S", "ns", "alice-source", "alice", false)).unwrap();
    ai_memory::db::insert(&conn, &mem("T", "ns", "bob-secret-title", "bob", true)).unwrap();
    ai_memory::db::insert(&conn, &mem("U", "ns", "alice-target", "alice", false)).unwrap();
    link(&conn, "S", "T");
    link(&conn, "S", "U");

    // caller = alice (owns S): source gate passes; bob's PRIVATE target T must
    // be filtered out, alice's own target U retained.
    let out = handle_kg_timeline(&conn, &json!({"source_id": "S"}), Some("alice")).unwrap();
    let t = titles(&out);
    assert!(
        !t.contains(&"bob-secret-title".to_string()),
        "#1804: alice must NOT see bob's private target title via kg_timeline; got {t:?}"
    );
    assert!(
        t.contains(&"alice-target".to_string()),
        "alice's own target must remain visible; got {t:?}"
    );

    // caller = None (single-tenant trust-all): unfiltered — both targets.
    let out_none = handle_kg_timeline(&conn, &json!({"source_id": "S"}), None).unwrap();
    let tn = titles(&out_none);
    assert!(
        tn.contains(&"bob-secret-title".to_string()) && tn.contains(&"alice-target".to_string()),
        "trust-all (caller=None) must be unfiltered; got {tn:?}"
    );
}
