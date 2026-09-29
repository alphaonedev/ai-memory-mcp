// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4061 — MCP `memory_update` must never drop a caller's compare-and-swap
//! fence because of the fence's JSON type.
//!
//! Before the fix `expected_version` was read with `as_i64()`, so a PRESENT
//! but wrong-typed value (`"1"`, `true`, `1.5`, an integer outside i64) read
//! as `None` — which storage treats as "no precondition" — and a stale full
//! replacement silently overwrote newer content. Driven through a real
//! `ai-memory mcp` child (the MCP path has no runtime JSON-Schema validation,
//! `src/mcp/param_guard.rs`).
//!
//! Cells:
//!   * RED on the untouched tip — each wrong-typed fence is refused and the
//!     row's content and version are unchanged.
//!   * controls — integer `1` (stale) is a conflict, integer `2` (current)
//!     succeeds, and an omitted fence is last-write-wins.

use ai_memory::models::{Memory, Tier};
use serde_json::{Value, json};

#[path = "common/mcp_wait.rs"]
mod mcp_wait;

#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;

use mcp_stdio_child::{Fixture, Mcp};

const AGENT: &str = "ai:cas4061";

fn seed(fixture: &Fixture) -> String {
    let conn = ai_memory::db::open(&fixture.db).expect("open");
    let now = chrono::Utc::now().to_rfc3339();
    let mem = Memory {
        id: uuid::Uuid::new_v4().to_string(),
        title: "cas4061".to_string(),
        content: "v1 body".to_string(),
        namespace: "cas4061".to_string(),
        tier: Tier::Long,
        metadata: json!({"agent_id": AGENT}),
        created_at: now.clone(),
        updated_at: now,
        ..Memory::default()
    };
    ai_memory::db::insert(&conn, &mem).expect("seed")
}

fn row(fixture: &Fixture, id: &str) -> (String, i64) {
    let conn = ai_memory::db::open(&fixture.db).expect("open");
    let mem = ai_memory::db::get(&conn, id)
        .expect("get")
        .expect("row present");
    (mem.content, mem.version)
}

fn update(mcp: &mut Mcp, id: &str, content: &str, fence: Option<Value>) -> Value {
    let mut args = json!({"id": id, "content": content});
    if let Some(fence) = fence {
        args["expected_version"] = fence;
    }
    mcp.call("memory_update", &args)
}

#[test]
fn wrong_typed_expected_version_is_refused_and_writes_nothing_4061() {
    let fixture = Fixture::new();
    let id = seed(&fixture);
    let mut mcp = Mcp::start(&fixture, Some(AGENT));
    // Advance the row to version 2 with a fenced, correct update.
    let bump = update(&mut mcp, &id, "v2 body", Some(json!(1)));
    assert_ne!(bump["isError"], true, "bump to v2: {bump}");
    assert_eq!(row(&fixture, &id), ("v2 body".to_string(), 2));

    let wrong_typed = [
        json!("1"),
        json!(true),
        json!(1.5),
        // Beyond i64::MAX: `as_i64()` reads it as None.
        json!(u64::MAX),
        json!({"version": 1}),
        json!([1]),
    ];
    for fence in wrong_typed {
        let result = update(&mut mcp, &id, "STALE overwrite", Some(fence.clone()));
        assert_eq!(
            result["isError"], true,
            "expected_version={fence} must be refused, not dropped: {result}"
        );
        assert!(
            Mcp::text(&result).contains("expected_version must be an integer"),
            "expected_version={fence}: typed parameter error, got {result}"
        );
        assert_eq!(
            row(&fixture, &id),
            ("v2 body".to_string(), 2),
            "expected_version={fence}: a refused update must not write"
        );
    }
}

#[test]
fn integer_and_absent_expected_version_keep_their_contract_4061() {
    let fixture = Fixture::new();
    let id = seed(&fixture);
    let mut mcp = Mcp::start(&fixture, Some(AGENT));
    let bump = update(&mut mcp, &id, "v2 body", None);
    assert_ne!(
        bump["isError"], true,
        "omitted fence is last-write-wins: {bump}"
    );
    assert_eq!(row(&fixture, &id), ("v2 body".to_string(), 2));

    let stale = update(&mut mcp, &id, "stale", Some(json!(1)));
    assert_eq!(
        stale["isError"], true,
        "stale integer fence conflicts: {stale}"
    );
    assert!(
        Mcp::text(&stale).contains("conflict"),
        "stale fence surfaces the conflict envelope: {stale}"
    );
    assert_eq!(row(&fixture, &id), ("v2 body".to_string(), 2));

    let current = update(&mut mcp, &id, "v3 body", Some(json!(2)));
    assert_ne!(
        current["isError"], true,
        "current fence succeeds: {current}"
    );
    assert_eq!(row(&fixture, &id), ("v3 body".to_string(), 3));

    let null_fence = update(&mut mcp, &id, "v4 body", Some(Value::Null));
    assert_ne!(
        null_fence["isError"], true,
        "null fence = no precondition: {null_fence}"
    );
    assert_eq!(row(&fixture, &id), ("v4 body".to_string(), 4));
}
