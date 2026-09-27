// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #4059 — `memory_skill_compositional_context` must render only the
//! reflections the CALLER may read.
//!
//! Pre-fix the handler selected reflection rows straight from `memories`
//! (namespace / kind / depth / expiry only) and returned their `title` and
//! `content`, with no caller-visibility predicate — and the #3549 structural
//! read guard exempted the tool as "not memory rows". A per-agent read
//! posture therefore did not hold across this tool: one agent's private
//! reflection was rendered to another agent composing a skill that declares
//! the namespace.
//!
//! Driven through real `ai-memory mcp` children bound (`AI_MEMORY_AGENT_ID`)
//! as each agent; every row is authored through the supported
//! `memory_store` → `memory_reflect` path.
//!
//! Cells:
//!   * RED on the untouched tip — each agent composes and receives its OWN
//!     private reflection plus the collective one, never the other agent's
//!     private reflection.
//!   * control — the no-identity local-operator posture (the documented
//!     single-tenant trust-all read) still composes every reflection.
//!   * structural — the tool is no longer allowlisted by the #3549 read
//!     guard, and its handler calls the canonical read funnel.

use serde_json::json;

#[path = "common/mcp_wait.rs"]
mod mcp_wait;

#[path = "common/mcp_stdio_child.rs"]
mod mcp_stdio_child;

use mcp_stdio_child::{Fixture, Mcp};

const NS: &str = "refl4059";
const ALICE: &str = "ai:alice-4059";
const BOB: &str = "ai:bob-4059";
const ALICE_SECRET: &str = "ALICE-PRIVATE-4059";
const BOB_SECRET: &str = "BOB-PRIVATE-4059";
const SHARED: &str = "COLLECTIVE-4059";

/// Author one observation + one reflection on it as `agent`, with the
/// reflection's `scope` set to `scope`.
fn author_reflection(fixture: &Fixture, agent: &str, marker: &str, scope: &str) {
    let mut mcp = Mcp::start(fixture, Some(agent));
    let stored = mcp.call_ok(
        "memory_store",
        &json!({
            "title": format!("source for {marker}"),
            "content": format!("observation behind {marker}"),
            "namespace": NS,
            "tier": "long",
        }),
    );
    let source = stored["id"]
        .as_str()
        .unwrap_or_else(|| panic!("memory_store id: {stored}"))
        .to_string();
    let reflected = mcp.call_ok(
        "memory_reflect",
        &json!({
            "source_ids": [source],
            "title": format!("reflection {marker}"),
            "content": marker,
            "namespace": NS,
            "metadata": {"scope": scope},
        }),
    );
    assert!(reflected.is_object(), "memory_reflect: {reflected}");
}

fn register_composing_skill(fixture: &Fixture) -> String {
    let mut mcp = Mcp::start(fixture, None);
    let md = format!(
        "---\nnamespace: skills4059\nname: composer-4059\ndescription: Composes {NS}.\n\
         composes_with_reflections:\n  - namespace: {NS}\n    min_depth: 0\n---\n\nCompose.\n"
    );
    let reg = mcp.call_ok("memory_skill_register", &json!({"inline_skill": md}));
    reg["id"]
        .as_str()
        .unwrap_or_else(|| panic!("skill_id: {reg}"))
        .to_string()
}

/// The reflection contents the `agent`-bound (or identity-less) caller
/// receives from the composition.
fn composed_contents(fixture: &Fixture, agent: Option<&str>, skill_id: &str) -> Vec<String> {
    let mut mcp = Mcp::start(fixture, agent);
    let out = mcp.call_ok(
        "memory_skill_compositional_context",
        &json!({"skill_id": skill_id}),
    );
    out["reflections"]
        .as_array()
        .unwrap_or_else(|| panic!("reflections array: {out}"))
        .iter()
        .map(|r| r["content"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn seeded() -> (Fixture, String) {
    let fixture = Fixture::new();
    author_reflection(&fixture, ALICE, ALICE_SECRET, "private");
    author_reflection(&fixture, BOB, BOB_SECRET, "private");
    author_reflection(&fixture, ALICE, SHARED, "collective");
    let skill_id = register_composing_skill(&fixture);
    (fixture, skill_id)
}

fn has(contents: &[String], marker: &str) -> bool {
    contents.iter().any(|c| c.contains(marker))
}

#[test]
fn each_agent_composes_only_the_reflections_it_may_read_4059() {
    let (fixture, skill_id) = seeded();

    let alice = composed_contents(&fixture, Some(ALICE), &skill_id);
    assert!(has(&alice, ALICE_SECRET), "alice sees her own: {alice:?}");
    assert!(
        has(&alice, SHARED),
        "alice sees the collective one: {alice:?}"
    );
    assert!(
        !has(&alice, BOB_SECRET),
        "alice must NOT receive bob's private reflection: {alice:?}"
    );

    let bob = composed_contents(&fixture, Some(BOB), &skill_id);
    assert!(has(&bob, BOB_SECRET), "bob sees his own: {bob:?}");
    assert!(has(&bob, SHARED), "bob sees the collective one: {bob:?}");
    assert!(
        !has(&bob, ALICE_SECRET),
        "bob must NOT receive alice's private reflection: {bob:?}"
    );

    let outsider = composed_contents(&fixture, Some("ai:mallory-4059"), &skill_id);
    assert!(
        !has(&outsider, ALICE_SECRET) && !has(&outsider, BOB_SECRET),
        "a third agent receives no private reflection: {outsider:?}"
    );
}

#[test]
fn local_operator_posture_is_unchanged_4059() {
    let (fixture, skill_id) = seeded();
    let operator = composed_contents(&fixture, None, &skill_id);
    for marker in [ALICE_SECRET, BOB_SECRET, SHARED] {
        assert!(
            has(&operator, marker),
            "the single-tenant trust-all posture composes {marker}: {operator:?}"
        );
    }
}

#[test]
fn compositional_context_is_funnelled_not_allowlisted_4059() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let allowlist =
        std::fs::read_to_string(root.join("tests/authority_boundary_3549_allowlist.txt"))
            .expect("read allowlist");
    let exempt = allowlist.lines().any(|l| {
        let mut cols = l.split('\t');
        cols.next() == Some("read") && cols.next() == Some("memory_skill_compositional_context")
    });
    assert!(
        !exempt,
        "memory_skill_compositional_context reads memory rows and must not be \
         exempted from the #3549 read funnel"
    );
    let handler =
        std::fs::read_to_string(root.join("src/mcp/tools/skill_compositional_context.rs"))
            .expect("read handler");
    let production = handler
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        production.contains("crate::visibility::is_readable_on_query("),
        "the compositional handler must call the canonical read funnel"
    );
    // The MCP dispatch must hand the resolved read caller to the handler.
    let mcp = std::fs::read_to_string(root.join("src/mcp/mod.rs")).expect("read mcp");
    let arm = mcp
        .split("fn dispatch_memory_skill_compositional_context(")
        .nth(1)
        .and_then(|rest| rest.split("\n}\n").next())
        .expect("dispatch arm");
    assert!(
        arm.contains("ctx.authority.read_caller()"),
        "the dispatch arm must pass the resolved read caller: {arm}"
    );
}
