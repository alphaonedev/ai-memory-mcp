// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3378 — `tools/list` compacted descriptions must keep the verb-noun
//! gist. `compact_description` used a hard 32-byte cut that left labels
//! ending on a dangling `+` or preposition.
//!
//! Denied path (the 2026-09-02 MCP-sweep findings, re-verified on
//! `origin/chain/next` = 1709b0a7):
//! - `memory_quota_status` shipped `"Report per-agent +"`
//! - `memory_skill_compositional_context` shipped `"Skill body +"`
//!
//! Allowed path: those two keep `per-namespace` / `composes_with_reflections`,
//! and no compacted full-profile `tools/list` description ends on a
//! dangling last token (`+`, preposition, article, conjunction).

use ai_memory::mcp::tool_definitions_for_profile;
use ai_memory::profile::Profile;

const DANGLING_LAST_TOKENS: &[&str] = &[
    "+", "-", "/", "to", "for", "of", "with", "from", "a", "an", "the", "and", "or", "per", "by",
    "in", "on", "at", "as", "into", "onto", "between", "over", "under", "via",
];

fn last_token(s: &str) -> &str {
    let s = s.trim_end_matches(|c: char| {
        c.is_whitespace() || matches!(c, '.' | ';' | ',' | ':' | ')' | '(' | '—' | '-')
    });
    s.rsplit(|c: char| c.is_whitespace() || c == '—')
        .next()
        .unwrap_or("")
}

fn compacted_description(name: &str) -> String {
    let defs = tool_definitions_for_profile(&Profile::full());
    let tools = defs["tools"].as_array().expect("tools array");
    for tool in tools {
        if tool.get("name").and_then(|n| n.as_str()) != Some(name) {
            continue;
        }
        if let Some(desc) = tool.get("description").and_then(|d| d.as_str()) {
            return desc.to_string();
        }
    }
    panic!("missing tool {name} on tools/list")
}

#[test]
fn quota_status_does_not_end_on_plus_3378() {
    let got = compacted_description("memory_quota_status");
    assert_ne!(
        got, "Report per-agent +",
        "denied: 32-byte cut left memory_quota_status as 'Report per-agent +'"
    );
    assert!(
        !got.ends_with('+'),
        "denied: compacted quota description ends on '+': {got:?}"
    );
    assert!(
        got.contains("per-namespace"),
        "allowed: gist must keep per-namespace, got {got:?}"
    );
}

#[test]
fn skill_body_does_not_end_on_plus_3378() {
    let got = compacted_description("memory_skill_compositional_context");
    assert_ne!(
        got, "Skill body +",
        "denied: 32-byte cut left memory_skill_compositional_context as 'Skill body +'"
    );
    assert!(
        !got.ends_with('+'),
        "denied: compacted skill description ends on '+': {got:?}"
    );
    assert!(
        got.contains("composes_with_reflections"),
        "allowed: gist must keep composes_with_reflections, got {got:?}"
    );
}

#[test]
fn no_compacted_full_profile_description_ends_dangling_3378() {
    let defs = tool_definitions_for_profile(&Profile::full());
    let tools = defs["tools"].as_array().expect("tools array");
    let mut offenders: Vec<String> = Vec::new();
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unnamed>");
        let desc = tool
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        let tok = last_token(desc);
        if DANGLING_LAST_TOKENS
            .iter()
            .any(|d| d.eq_ignore_ascii_case(tok))
        {
            offenders.push(format!("{name}: {desc:?}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "compacted tools/list descriptions must not end on a dangling last token \
         (#3378):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn forget_compact_does_not_keep_trailing_comma_3378() {
    let got = compacted_description("memory_forget");
    assert_ne!(
        got, "Bulk delete memories matching a pattern,",
        "denied: unit-1 word-walk left memory_forget ending on 'pattern,'"
    );
    assert!(
        !got.ends_with(',') && !got.ends_with(':'),
        "denied: compacted forget description kept trailing punctuation: {got:?}"
    );
    assert!(
        got.contains("pattern"),
        "allowed: gist must keep 'pattern', got {got:?}"
    );
}

#[test]
fn no_compacted_full_profile_description_ends_on_comma_or_colon_3378() {
    let defs = tool_definitions_for_profile(&Profile::full());
    let tools = defs["tools"].as_array().expect("tools array");
    let mut offenders: Vec<String> = Vec::new();
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unnamed>");
        let desc = tool
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        if desc.ends_with(',') || desc.ends_with(':') {
            offenders.push(format!("{name}: {desc:?}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "compacted tools/list descriptions must not end on ',' or ':' \
         (#3378 unit 2):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn every_non_capabilities_description_points_at_memory_capabilities_3378() {
    let defs = tool_definitions_for_profile(&Profile::full());
    let tools = defs["tools"].as_array().expect("tools array");
    let mut missing: Vec<String> = Vec::new();
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("<unnamed>");
        if name == "memory_capabilities" {
            continue;
        }
        let desc = tool
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("");
        if !desc.contains("memory_capabilities") {
            missing.push(format!("{name}: {desc:?}"));
        }
    }
    assert!(
        missing.is_empty(),
        "every compacted tools/list description except memory_capabilities \
         itself must point at memory_capabilities (#3378 unit 3):\n{}",
        missing.join("\n")
    );
}

#[test]
fn memory_capabilities_description_does_not_self_point_3378() {
    let got = compacted_description("memory_capabilities");
    assert!(
        !got.contains("See memory_capabilities"),
        "memory_capabilities must not point at itself: {got:?}"
    );
}
