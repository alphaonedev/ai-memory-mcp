// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

// clippy allows (test scaffolding): pedantic lints with no behavioral impact.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc)]
//! Boids item 3 f1-review F1, SQLite parity (ruling `ITEM3-P1P4-f1`): the
//! #3324 MCP narrow trigger stamps the superseded target's descendants under
//! the CALLER's authority. With `AI_MEMORY_AGENT_ID` set (multi-tenant), the
//! #1929 target gate already requires the caller to own the target, but the
//! descendant closure was stamped regardless of owner — a PRE-EXISTING flaw
//! (since #3324): another owner's private descendant was contaminated. RED on
//! 362b505ab: the victim's descendant reads `contaminated`.
//!
//! The configured-caller cell runs in a child process (the #3498 pattern) so
//! the process-global env var cannot leak into sibling suites.

use ai_memory::db;
use ai_memory::models::{Memory, MemoryKind};
use serde_json::json;

const CALLER: &str = "ai:f1-owner";
const VICTIM: &str = "ai:f1-victim";

fn seed(conn: &rusqlite::Connection, owner: &str, kind: MemoryKind, private: bool) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let mut metadata = json!({"agent_id": owner});
    if private {
        metadata["scope"] = json!("private");
    }
    let m = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        namespace: "f1/authz".to_string(),
        title: format!("f1 {}", uuid::Uuid::new_v4()),
        content: "f1 authz".to_string(),
        created_at: now.clone(),
        updated_at: now,
        metadata,
        memory_kind: kind,
        reflection_depth: i32::from(kind == MemoryKind::Reflection),
        ..Memory::default()
    };
    db::insert(conn, &m).expect("seed")
}

fn state(conn: &rusqlite::Connection, id: &str) -> String {
    conn.query_row(
        "SELECT lifecycle_state FROM memories WHERE id = ?1",
        [id],
        |r| r.get(0),
    )
    .expect("state")
}

/// Superseder S + superseded T (both the caller's reflections), T's
/// derives_from descendants: one the caller's, one a victim's private row.
/// Returns `(own_child, victim_child)` after the MCP supersedes.
fn run_supersede(path: &std::path::Path) -> (String, String, serde_json::Value) {
    let conn = db::open(path).expect("open");
    let s = seed(&conn, CALLER, MemoryKind::Reflection, false);
    let t = seed(&conn, CALLER, MemoryKind::Reflection, false);
    let own = seed(&conn, CALLER, MemoryKind::Observation, false);
    let victim = seed(&conn, VICTIM, MemoryKind::Observation, true);
    for child in [&own, &victim] {
        db::create_link(&conn, child, &t, "derives_from").expect("lineage");
    }
    let resp = ai_memory::mcp::dispatch_handle_link_for_test(
        &conn,
        path,
        &json!({"source_id": s, "target_id": t, "relation": "supersedes", "agent_id": CALLER}),
        None,
    )
    .expect("supersedes link commits");
    (state(&conn, &own), state(&conn, &victim), resp)
}

#[test]
fn sqlite_nonadmin_supersedes_stamps_only_the_callers_own_descendants_f1() {
    const CHILD: &str = "AI_MEMORY_F1_SQLITE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("exe"))
            .args([
                "--exact",
                "sqlite_nonadmin_supersedes_stamps_only_the_callers_own_descendants_f1",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("AI_MEMORY_AGENT_ID", CALLER)
            .output()
            .expect("isolated caller process");
        assert!(
            output.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let (own, victim, resp) = run_supersede(std::path::Path::new(":memory:"));
    assert_eq!(
        own, "contaminated",
        "the caller's own descendant is stamped"
    );
    assert_eq!(
        victim, "open",
        "a victim's private descendant is outside the caller's authority"
    );
    assert_eq!(resp["contaminated_stamped"].as_u64(), Some(1), "{resp}");
}

/// Trust-all (no `AI_MEMORY_AGENT_ID`) is the single operator — admin-
/// equivalent — so the whole closure is still stamped (non-regression).
#[test]
fn sqlite_trust_all_operator_still_stamps_across_owners_f1() {
    const CHILD: &str = "AI_MEMORY_F1_SQLITE_TRUSTALL_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("exe"))
            .args([
                "--exact",
                "sqlite_trust_all_operator_still_stamps_across_owners_f1",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env_remove("AI_MEMORY_AGENT_ID")
            .output()
            .expect("isolated operator process");
        assert!(
            output.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let (own, victim, _) = run_supersede(std::path::Path::new(":memory:"));
    assert_eq!(own, "contaminated");
    assert_eq!(victim, "contaminated", "the operator stamps across owners");
}
