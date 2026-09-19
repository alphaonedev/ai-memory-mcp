// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3373 (review) — `memory_load_family` projects every column now, so it
//! REACHES a sealed row's `encrypted_envelope`. A family read is a discovery
//! scan (like `get_many`, #2383 N1): one row whose envelope will not open —
//! a lost key, a corrupt envelope — must be SKIPPED, and every other row in
//! the family still returned, instead of one poisoned row failing the whole
//! call for every caller. The envelope is made unopenable here by writing
//! bytes no key opens straight into the column (the decrypt branch is gated
//! on envelope PRESENCE, not on the at-rest flag, so no env or key-dir
//! state is touched); the lost-key shape of the same failure is pinned by
//! the #3718 suite.
//!
//! On the pre-#3373 head the loader never projected the envelope, so this
//! cell fails there for the opposite reason: the undecryptable row is served
//! with EMPTY placeholder content and counted (count == 2). On the first
//! #3373 cut (`SELECT *` + fail-closed mapper) the call itself errs. On the
//! fixed branch: `Ok`, the readable row present, the unreadable one absent.
//!
//! Lives in its own file (not the `src/mcp/mod.rs` test module) because
//! that module sits two lines under its QUAL-10 ceiling.

use ai_memory::db;
use ai_memory::mcp::handle_load_family;
use ai_memory::models::{ConfidenceSource, Memory, MemoryKind, Tier};
use serde_json::json;
use std::path::Path;

#[path = "common/key_dir_sandbox.rs"]
mod key_dir_sandbox;

fn family_row(title: &str, namespace: &str, agent_id: &str) -> Memory {
    let now = chrono::Utc::now().to_rfc3339();
    Memory {
        id: uuid::Uuid::new_v4().to_string(),
        tier: Tier::Mid,
        namespace: namespace.to_string(),
        title: title.to_string(),
        content: format!("{title} — sealed family content (#3373)"),
        tags: vec![],
        priority: 5,
        confidence: 1.0,
        source: "import".to_string(),
        access_count: 0,
        created_at: now.clone(),
        updated_at: now,
        last_accessed_at: None,
        expires_at: None,
        metadata: json!({"family": "core", "agent_id": agent_id}),
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
        ..Memory::default()
    }
}

#[test]
fn load_family_skips_the_undecryptable_row_and_returns_the_rest_3373() {
    // Key operations, if any path reaches one, land in a sandbox — never in
    // an operator's key directory.
    let _key_dir = key_dir_sandbox::pin();
    let conn = db::open(Path::new(":memory:")).expect("open in-memory db");
    let ns = "ns-3373-sealed";
    let lost = format!("agent-3373-lost-{}", uuid::Uuid::new_v4().simple());
    let kept = format!("agent-3373-kept-{}", uuid::Uuid::new_v4().simple());

    // Two family rows; the first gets an envelope no key can open (a
    // version byte the opener rejects, placeholder content), the second stays
    // readable.
    let lost_id = db::insert(&conn, &family_row("lost-key row", ns, &lost)).expect("insert lost");
    let kept_id = db::insert(&conn, &family_row("kept-key row", ns, &kept)).expect("insert kept");
    // 48 bytes: too short for any envelope layout, so the opener rejects it
    // before touching a key (no keypair is minted for the "lost" agent).
    let unopenable: Vec<u8> = vec![0xff; 48];
    let n = conn
        .execute(
            "UPDATE memories SET encrypted_envelope = ?1, content = '' WHERE id = ?2",
            rusqlite::params![unopenable, lost_id],
        )
        .expect("poison the envelope");
    assert_eq!(n, 1);
    let err = db::get(&conn, &lost_id).expect_err("the single-row read fails closed on it");
    assert!(!format!("{err}").is_empty());

    // The family read is a discovery scan: Ok, the readable row present, the
    // undecryptable row ABSENT (never served as empty placeholder content,
    // never failing the whole call).
    let resp = handle_load_family(
        &conn,
        &json!({"family": "core", "namespace": ns, "k": 10}),
        None,
    )
    .expect("#3373: one undecryptable row must not fail the whole family read");
    let rows = resp["memories"].as_array().expect("memories array");
    let ids: Vec<&str> = rows.iter().filter_map(|m| m["id"].as_str()).collect();
    assert!(
        ids.contains(&kept_id.as_str()),
        "the readable row is returned: {ids:?}"
    );
    assert!(
        !ids.contains(&lost_id.as_str()),
        "#3373: the undecryptable row is skipped, not served empty: {ids:?}"
    );
    assert_eq!(
        resp["count"],
        json!(1),
        "count reflects the rows actually served: {resp}"
    );
    let kept_row = rows
        .iter()
        .find(|m| m["id"] == json!(kept_id))
        .expect("kept row");
    assert_eq!(
        kept_row["content"],
        json!("kept-key row — sealed family content (#3373)"),
        "the readable row carries its content, not a placeholder"
    );
}
